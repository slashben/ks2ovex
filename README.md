# Tool for converting Kubescape vulnerability objects to OpenVEX

This is a command line tool for converting Kubescape vulnerability objects to OpenVEX format.

## Usage

After cloning this repo, run:
```bash
go mod tidy
go run cmd/main.go data/gcr.io-google-samples-microservices-demo-adservice-v0.8.0-c5b75f.json data/default-replicaset-adservice-7d857689bd-b630-5e48.json
```

You will get [this](data/gcr.io-google-samples-microservices-demo-adservice-v0.8.0.vex) in the stdout:
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-567f9d48cbf740f635d324a7a511fc7fd19a25412494c528ec37eb9e49e75923",
  "author": "Kubescape vulnerability scanner",
  "role": "Senior open source project :)",
  "timestamp": "2023-10-11T12:44:05.299994172+03:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2020-8908",
        "name": "CVE-2020-8908",
        "description": "A temp directory creation vulnerability exists in all versions of Guava, allowing an attacker with access to the machine to potentially access data in a temporary directory created by the Guava API com.google.common.io.Files.createTempDir(). By default, on unix-like systems, the created directory is world-readable (readable by an attacker with access to the system). The method in question has been marked @Deprecated in versions 30.0 and later and should not be used. For Android developers, we recommend choosing a temporary directory API provided by Android, such as context.getCacheDir(). For other Java developers, we recommend migrating to the Java 7 API java.nio.file.Files.createTempDirectory() which explicitly configures permissions of 700, or configuring the Java runtime's java.io.tmpdir system property to point to a location whose permissions are appropriately configured.\n\n"
      },
      "products": [
        {
          "@id": "gcr.io/google-samples/microservices-demo/adservice@sha256:45fb8ed886902c0c49e044b1f8870fad61c1022fa23c4943098302a8f1c5b75f",
          "identifiers": {
            "cpe23": "cpe:2.3:a:guava:guava:31.1-android:*:*:*:*:*:*:*",
            "purl": "pkg:maven/com.google.guava/guava@31.1-android"
          }
        }
      ],
      "status": "affected",
      "impact_statement": "Vulnerable component is loaded into the memory"
    },
...
```