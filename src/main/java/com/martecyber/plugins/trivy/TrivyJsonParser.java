package com.martecyber.plugins.trivy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parses {@code trivy fs/repo ... --format json} output.
 *
 * Trivy self-identifies the scanned project via a {@code Packages[]} entry with
 * {@code "Relationship": "root"} (full package coordinates, parsed straight from the
 * manifest — pom.xml, package.json, etc.), so unlike a network scanner there's no
 * separate "which asset is this?" step: the root package becomes a {@link AssetType#SOFTWARE}
 * asset, every other package in the same {@code Results[]} entry becomes a
 * {@link AssetType#TECHNOLOGY} dependency linked to it, and every vulnerability is
 * reported as a detection detected on (and affecting) that same SOFTWARE asset —
 * never the individual dependency it was found in — mirroring how {@code WPScanJSONParser}
 * always attaches plugin/theme vulnerabilities to the root WordPress web application.
 *
 * Maven is the only ecosystem where Trivy actually emits a {@code "root"} package —
 * confirmed empirically: npm/pnpm never mark one (even for a single, non-workspace
 * project with the manifest and lockfile in the same directory), and Python without a
 * lockfile (a bare {@code pyproject.toml}) isn't analyzed at all. For those, this parser
 * falls back to the scan's own top-level {@code ArtifactName} (i.e. whatever path was
 * passed to {@code trivy fs ...} — "ares-ui", "ares-cli", etc.) as the SOFTWARE
 * identifier, so every package in that {@code Results[]} entry becomes a dependency of
 * it. Only when even that is blank (or the whole scan produced no packages) is anything
 * skipped, with a warning.
 */
@Component
public class TrivyJsonParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId() { return "trivy"; }
    @Override public String getDisplayName() { return "Trivy JSON"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".json"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        return s.contains("\"ArtifactName\"") && s.contains("\"Results\"");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        JsonNode root = MAPPER.readTree(content);

        JsonNode results = root.get("Results");
        if (results == null || !results.isArray()) return result;

        String artifactName = text(root, "ArtifactName");
        for (JsonNode r : results) {
            processResult(r, artifactName, result);
        }
        return result;
    }

    private void processResult(JsonNode r, String artifactName, ParseResult result) {
        JsonNode packages = r.get("Packages");
        if (packages == null || !packages.isArray()) return;

        JsonNode rootPkg = null;
        for (JsonNode p : packages) {
            if ("root".equals(text(p, "Relationship"))) { rootPkg = p; break; }
        }

        String softwareId;
        Map<String, Object> softwareMeta = new LinkedHashMap<>();
        if (rootPkg != null) {
            softwareId = text(rootPkg, "Name");
            if (softwareId == null || softwareId.isBlank()) softwareId = purl(rootPkg);
            putIfPresent(softwareMeta, "version", text(rootPkg, "Version"));
            putIfPresent(softwareMeta, "purl", purl(rootPkg));
        } else {
            // No self-identifying root package in this ecosystem (npm/pnpm/pip) — fall back
            // to the scan's own target name (see class javadoc).
            softwareId = artifactName;
        }
        if (softwareId == null || softwareId.isBlank()) {
            result.addWarning("Skipping '" + text(r, "Target") + "': no usable software identifier " +
                "(no root package, and no ArtifactName on the scan)");
            return;
        }

        putIfPresent(softwareMeta, "target", text(r, "Target"));
        putIfPresent(softwareMeta, "packageType", text(r, "Type"));
        result.addAsset(new ParsedAsset(softwareId, AssetType.SOFTWARE, softwareMeta));

        for (JsonNode p : packages) {
            if (p == rootPkg) continue;
            String techId = purl(p);
            if (techId == null || techId.isBlank()) {
                String name = text(p, "Name");
                String ver = text(p, "Version");
                if (name == null) continue;
                techId = ver != null ? name + "@" + ver : name;
            }
            Map<String, Object> techMeta = new LinkedHashMap<>();
            putIfPresent(techMeta, "name", text(p, "Name"));
            putIfPresent(techMeta, "version", text(p, "Version"));
            putIfPresent(techMeta, "relationship", text(p, "Relationship"));
            result.addAsset(new ParsedAsset(techId, AssetType.TECHNOLOGY, techMeta));
            result.addLink(softwareId, techId, AssetLinkType.SOFTWARE_TECHNOLOGY);
        }

        JsonNode vulns = r.get("Vulnerabilities");
        if (vulns == null || !vulns.isArray()) return;
        for (JsonNode v : vulns) {
            processVulnerability(v, softwareId, result);
        }
    }

    private void processVulnerability(JsonNode v, String softwareId, ParseResult result) {
        String vulnId = text(v, "VulnerabilityID");
        String pkgName = text(v, "PkgName");
        String installedVersion = text(v, "InstalledVersion");
        String fixedVersion = text(v, "FixedVersion");
        String severity = text(v, "Severity");
        String primaryUrl = text(v, "PrimaryURL");
        String trivyTitle = text(v, "Title");
        String trivyDescription = text(v, "Description");

        // Trivy's own Title already names the affected package for most advisories (e.g.
        // "jackson-core: Async parser ..."), so only prefix it ourselves when falling back
        // to a bare vulnerability ID — otherwise every title would double up the package name.
        String title;
        if (trivyTitle != null) {
            title = trivyTitle;
        } else {
            String fallback = "Vulnerability " + (vulnId != null ? vulnId : "unknown");
            title = pkgName != null ? pkgName + ": " + fallback : fallback;
        }
        if (title.length() > 300) title = title.substring(0, 297) + "...";

        StringBuilder desc = new StringBuilder();
        if (vulnId != null) desc.append(vulnId).append('\n');
        if (pkgName != null) {
            desc.append("Package: ").append(pkgName);
            if (installedVersion != null) desc.append(" (installed: ").append(installedVersion).append(")");
            desc.append('\n');
        }
        if (fixedVersion != null) desc.append("Fixed in: ").append(fixedVersion).append('\n');
        if (trivyDescription != null) desc.append('\n').append(trivyDescription);
        if (primaryUrl != null) desc.append("\n\nReference: ").append(primaryUrl);

        String raw;
        try { raw = MAPPER.writeValueAsString(v); } catch (Exception e) { raw = "{}"; }

        // Trivy's Status field ("fixed", "affected", ...) describes whether an upstream fix
        // exists for this advisory — not whether the scanned artifact has already applied it.
        // Every vulnerability Trivy reports is present in the artifact as scanned, so this is
        // always an active finding; there is no "state" input to ParsedDetection here.
        //
        // sourceTemplateId includes the package name because the same VulnerabilityID can be
        // reported against two different dependencies of the same project (e.g. a Netty CVE
        // hitting both netty-codec-http and netty-codec-http2) — using the bare VulnerabilityID
        // would collide in ImportService's per-asset dedup hash and silently drop one of them.
        String templateId = pkgName != null ? vulnId + "@" + pkgName : vulnId;
        result.addDetection(new ParsedDetection(
            title, severity, desc.toString().trim(), softwareId, templateId, raw
        ));
    }

    private static String purl(JsonNode pkg) {
        JsonNode id = pkg.get("Identifier");
        return id != null ? text(id, "PURL") : null;
    }

    private static void putIfPresent(Map<String, Object> meta, String key, String value) {
        if (value != null && !value.isBlank()) meta.put(key, value);
    }

    private static String text(JsonNode node, String field) {
        if (node == null) return null;
        JsonNode n = node.get(field);
        return (n != null && !n.isNull() && n.isTextual() && !n.asText().isBlank()) ? n.asText() : null;
    }
}
