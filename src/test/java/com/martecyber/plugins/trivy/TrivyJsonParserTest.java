package com.martecyber.plugins.trivy;

import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link TrivyJsonParser}: the self-identifying "root" Maven package becoming the
 *  SOFTWARE asset with every sibling package as a TECHNOLOGY dependency, the ArtifactName
 *  fallback for ecosystems (npm/pip) that never mark a root package, and the per-package
 *  templateId disambiguation for one CVE hitting two different dependencies. */
class TrivyJsonParserTest {

    private final TrivyJsonParser parser = new TrivyJsonParser();

    private ParseResult parse(String json) throws Exception {
        return parser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRequiresArtifactNameAndResults() {
        assertTrue(parser.validate("{\"ArtifactName\":\"x\",\"Results\":[]}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("{\"ArtifactName\":\"x\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rootPackageBecomesTheSoftwareAssetAndSiblingsBecomeTechnologyDependencies() throws Exception {
        ParseResult result = parse("""
            {"ArtifactName":"ares-core","Results":[{"Target":"pom.xml","Type":"jar","Packages":[
              {"Name":"com.martecyber:ares-core","Version":"1.0","Relationship":"root",
               "Identifier":{"PURL":"pkg:maven/com.martecyber/ares-core@1.0"}},
              {"Name":"com.fasterxml.jackson.core:jackson-core","Version":"2.17.0",
               "Relationship":"direct","Identifier":{"PURL":"pkg:maven/jackson-core@2.17.0"}}
            ]}]}
            """);

        ParsedAsset software = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.SOFTWARE)).findFirst().orElseThrow();
        assertEquals("com.martecyber:ares-core", software.getIdentifier());
        assertEquals("1.0", software.getMetadata().get("version"));
        assertEquals("pom.xml", software.getMetadata().get("target"));

        ParsedAsset tech = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.TECHNOLOGY)).findFirst().orElseThrow();
        assertEquals("pkg:maven/jackson-core@2.17.0", tech.getIdentifier());
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.SOFTWARE_TECHNOLOGY)
            && l.getFromIdentifier().equals("com.martecyber:ares-core")
            && l.getToIdentifier().equals("pkg:maven/jackson-core@2.17.0")));
    }

    @Test
    void fallsBackToArtifactNameWhenNoPackageIsMarkedRoot() throws Exception {
        // npm/pnpm never mark a "root" package — see the class javadoc.
        ParseResult result = parse("""
            {"ArtifactName":"ares-ui","Results":[{"Target":"package-lock.json","Type":"npm","Packages":[
              {"Name":"left-pad","Version":"1.3.0"}
            ]}]}
            """);

        ParsedAsset software = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.SOFTWARE)).findFirst().orElseThrow();
        assertEquals("ares-ui", software.getIdentifier());
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.TECHNOLOGY) && a.getIdentifier().equals("left-pad@1.3.0")));
    }

    @Test
    void resultWithNoUsableSoftwareIdentifierIsSkippedWithAWarning() throws Exception {
        ParseResult result = parse("""
            {"Results":[{"Target":"requirements.txt","Packages":[{"Name":"flask","Version":"2.0"}]}]}
            """);
        assertTrue(result.getAssets().isEmpty());
        assertFalse(result.getWarnings().isEmpty());
    }

    @Test
    void vulnerabilityDescriptionAndTitleUseTrivysOwnFieldsWhenPresent() throws Exception {
        ParseResult result = parse("""
            {"ArtifactName":"ares-core","Results":[{"Target":"pom.xml","Packages":[
              {"Name":"root-pkg","Version":"1.0","Relationship":"root"}
            ],"Vulnerabilities":[
              {"VulnerabilityID":"CVE-2024-1234","PkgName":"jackson-core","InstalledVersion":"2.15.0",
               "FixedVersion":"2.17.0","Severity":"CRITICAL","Title":"jackson-core: Deserialization RCE",
               "Description":"A crafted payload can trigger RCE.","PrimaryURL":"https://example.com/cve"}
            ]}]}
            """);

        ParsedDetection d = result.getDetections().get(0);
        assertEquals("jackson-core: Deserialization RCE", d.getTitle());
        // ParsedDetection's own constructor normalizes severity case/spelling — Trivy's raw
        // "CRITICAL" becomes the canonical lowercase "critical" regardless of what the parser passed.
        assertEquals("critical", d.getSeverity());
        assertEquals("root-pkg", d.getAssetIdentifier());
        assertEquals("CVE-2024-1234@jackson-core", d.getSourceTemplateId());
        assertTrue(d.getDescription().contains("Package: jackson-core (installed: 2.15.0)"));
        assertTrue(d.getDescription().contains("Fixed in: 2.17.0"));
        assertTrue(d.getDescription().contains("A crafted payload can trigger RCE."));
        assertTrue(d.getDescription().contains("Reference: https://example.com/cve"));
    }

    @Test
    void vulnerabilityWithoutATrivyTitleFallsBackToPackagePrefixedVulnerabilityId() throws Exception {
        ParseResult result = parse("""
            {"ArtifactName":"ares-core","Results":[{"Target":"pom.xml","Packages":[
              {"Name":"root-pkg","Version":"1.0","Relationship":"root"}
            ],"Vulnerabilities":[
              {"VulnerabilityID":"CVE-2024-9999","PkgName":"some-lib","Severity":"LOW"}
            ]}]}
            """);
        assertEquals("some-lib: Vulnerability CVE-2024-9999", result.getDetections().get(0).getTitle());
    }

    @Test
    void sameVulnerabilityIdAgainstTwoDifferentPackagesGetsDistinctTemplateIds() throws Exception {
        ParseResult result = parse("""
            {"ArtifactName":"ares-core","Results":[{"Target":"pom.xml","Packages":[
              {"Name":"root-pkg","Version":"1.0","Relationship":"root"}
            ],"Vulnerabilities":[
              {"VulnerabilityID":"CVE-2024-1111","PkgName":"netty-codec-http","Severity":"HIGH"},
              {"VulnerabilityID":"CVE-2024-1111","PkgName":"netty-codec-http2","Severity":"HIGH"}
            ]}]}
            """);
        var templateIds = result.getDetections().stream().map(ParsedDetection::getSourceTemplateId).toList();
        assertEquals(2, new java.util.HashSet<>(templateIds).size());
    }

    @Test
    void resultsArrayMissingOrEmptyProducesAnEmptyResultWithoutThrowing() throws Exception {
        assertTrue(parse("{\"ArtifactName\":\"x\"}").getAssets().isEmpty());
        assertTrue(parse("{\"ArtifactName\":\"x\",\"Results\":[]}").getDetections().isEmpty());
    }

    @Test
    void repositoryScanUsesTheRepoUrlEvenWithARootPackage() throws Exception {
        ParseResult result = parse("""
            {"ArtifactName":"https://github.com/acme/app","ArtifactType":"repository","Results":[
              {"Target":"pom.xml","Type":"pom","Packages":[
                {"Name":"com.acme:app","Version":"2.0","Relationship":"root",
                 "Identifier":{"PURL":"pkg:maven/com.acme/app@2.0"}},
                {"Name":"org.yaml:snakeyaml","Version":"1.30","Relationship":"direct",
                 "Identifier":{"PURL":"pkg:maven/org.yaml/snakeyaml@1.30"}}],
               "Vulnerabilities":[{"VulnerabilityID":"CVE-2022-1471","PkgName":"org.yaml:snakeyaml",
                 "InstalledVersion":"1.30","Severity":"HIGH","Title":"snakeyaml: Constructor deserialization"}]}
            ]}
            """);

        ParsedAsset software = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.SOFTWARE)).findFirst().orElseThrow();
        assertEquals("https://github.com/acme/app", software.getIdentifier());
        assertEquals("com.acme:app", software.getMetadata().get("rootPackage"));
        assertEquals("repository", software.getMetadata().get("artifactType"));
        assertEquals(1, result.getDetections().size());
        assertEquals("https://github.com/acme/app", result.getDetections().get(0).getAssetIdentifier());
    }

    @Test
    void imageScanUsesTheImageReferenceForOsAndLanguagePackages() throws Exception {
        ParseResult result = parse("""
            {"ArtifactName":"python:3.9-alpine3.18","ArtifactType":"container_image","Results":[
              {"Target":"python:3.9-alpine3.18 (alpine 3.18.6)","Class":"os-pkgs","Type":"alpine","Packages":[
                {"Name":"openssl","Version":"3.1.4-r5","Identifier":{"PURL":"pkg:apk/alpine/openssl@3.1.4-r5"}}],
               "Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0727","PkgName":"openssl",
                 "InstalledVersion":"3.1.4-r5","Severity":"MEDIUM","Title":"openssl: denial of service"}]},
              {"Target":"Python","Class":"lang-pkgs","Type":"python-pkg","Packages":[
                {"Name":"setuptools","Version":"58.1.0","Identifier":{"PURL":"pkg:pypi/setuptools@58.1.0"}}],
               "Vulnerabilities":[{"VulnerabilityID":"CVE-2022-40897","PkgName":"setuptools",
                 "InstalledVersion":"58.1.0","Severity":"MEDIUM","Title":"setuptools: ReDoS"}]}
            ]}
            """);

        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals(AssetType.SOFTWARE))
            .map(ParsedAsset::getIdentifier).distinct().count());
        assertTrue(result.getDetections().stream()
            .allMatch(d -> d.getAssetIdentifier().equals("python:3.9-alpine3.18")));
        assertEquals(2, result.getDetections().size());
    }
}
