# Migration Guide: Ghidra 11.1 → 12.0

This document describes every change made to update Cartographer from Ghidra 11.1 (as of July 2024) to Ghidra 12.0.

---

## Summary

| Area | Change |
|------|--------|
| `build.gradle` | Source-tree support, Maven deps, classpath isolation fix |
| `CartographerPlugin.java` | Decompiler highlighting rewritten to use public API |

No other source files required changes.

---

## 1. `build.gradle`

### 1.1 Source-tree build support

The original script assumed a binary Ghidra distribution and applied only one path for `buildExtension.gradle`. The updated script probes both locations:

```groovy
def binaryScript = "${ghidraInstallDir}/support/buildExtension.gradle"
def sourceScript = "${ghidraInstallDir}/Ghidra/RuntimeScripts/Common/support/buildExtension.gradle"
```

This allows building against either a binary release or a source checkout of Ghidra.

### 1.2 Maven dependencies for compilation

Ghidra 12.0's module JARs reference types from several third-party libraries. `javac` needs these on the compile classpath to resolve Ghidra API signatures. Added as `compileOnly` (not bundled into the extension):

- `com.google.guava:guava`, `failureaccess`
- `org.jdom:jdom2`
- `org.apache.logging.log4j:log4j-api`, `log4j-core`
- `org.apache.commons:commons-collections4`, `commons-compress`, `commons-lang3`, `commons-text`
- `commons-codec:commons-codec`, `commons-io:commons-io`
- `com.google.code.gson:gson`
- `org.bouncycastle:bcpkix-jdk18on`, `bcprov-jdk18on`, `bcutil-jdk18on`
- `com.formdev:flatlaf`

### 1.3 `ghidraBuildTools` configuration (classpath isolation)

Ghidra's `buildModuleHelp` task assembles its classpath from `sourceSets.main.runtimeClasspath`, which already contains all Ghidra module JARs. Adding the Maven deps to `runtimeClasspath` (or `compileClasspath`) would duplicate those module entries and cause:

```
AssertException: Multiple modules collided with same name: SoftwareModeling
```

The fix introduces a separate `ghidraBuildTools` resolvable configuration (containing only the Maven JARs plus `javahelp`) and appends it to all `JavaExec` tasks via `afterEvaluate`. This keeps the Ghidra module JARs present exactly once.

### 1.4 `ADDITIONAL_APPLICATION_ROOT_DIRS` removal for source-tree builds

`buildExtension.gradle` passes `ADDITIONAL_APPLICATION_ROOT_DIRS=${ghidraInstallDir}/Ghidra` as a JVM system property to `buildModuleHelp`. In a binary distribution this is the only way for `GenericApplicationLayout` to find the Ghidra root.

In a source-tree build, however, `SystemUtilities.isInDevelopmentMode()` returns `true` (because module class files reside under `build/libs/`). `GenericApplicationLayout` then *also* discovers the same root via classpath scanning, adding it twice and triggering the same module-collision error.

The fix removes the property from `buildModuleHelp`'s `systemProperties` map inside `afterEvaluate`; dev-mode auto-discovery provides it exactly once.

---

## 2. `CartographerPlugin.java` — decompiler highlighting

### Root cause

The original plugin obtained a reference to the internal `DecompilerController` class and replaced its `callbackHandler` field via `TestUtils.setInstanceField()` (Ghidra's test utility, not part of the public API). Starting with Ghidra 11.2 the `callbackHandler` field was made `final`, and Java 21 (required by Ghidra 11.3+) enforces `final` field immutability even through reflection, so `setInstanceField()` throws `IllegalAccessException` at runtime.

### Solution

Replaced the entire approach with `DecompilerHighlightService`, Ghidra's official public API for decompiler background highlighting, available since Ghidra 10.2.

**Before** (broken in Ghidra 11.2+ / Java 21):
```java
// Reach into internals via reflection
TestUtils.setInstanceField("callbackHandler", controller, myHandler);
```

**After** (DecompilerHighlightService public API, available since Ghidra 10.2):
```java
DecompilerHighlightService svc = tool.getService(DecompilerHighlightService.class);
decompilerHighlighter = svc.createHighlighter(DECOMPILER_HIGHLIGHTER_ID,
    new CTokenHighlightMatcher() {
        private AddressSetView coveredSet = new AddressSet();

        @Override
        public void start(ClangNode root) {
            // Build a covered-address set once per decompile pass (O(log n) lookups)
            AddressSet set = new AddressSet();
            if (loaded && provider.getSelectedFile() != null) {
                provider.getSelectedFile().getCoverageFunctions()
                    .forEach((fn, ccFunc) -> {
                        for (CodeBlock block : ccFunc.getBlocksHit()) {
                            set.add(block);
                        }
                    });
            }
            coveredSet = set;
        }

        @Override
        public Color getTokenHighlight(ClangToken token) {
            Address addr = token.getMinAddress();
            if (addr == null || coveredSet.isEmpty()) return null;
            return coveredSet.contains(addr) ? provider.getDecompilerColor() : null;
        }
    });
```

`decompilerHighlighter.applyHighlights()` triggers re-highlighting whenever coverage data or the highlight color changes; `decompilerHighlighter.dispose()` is called in `CartographerPlugin.dispose()`.

### Removed APIs / imports

The following internal / test-only APIs were removed:

- `ghidra.test.TestUtils` (test utility, not for production)
- `ghidra.app.decompiler.component.ClangLayoutController`
- `ghidra.app.decompiler.component.DecompilerCallbackHandler`
- `ghidra.app.decompiler.component.DecompilerController`
- `ghidra.app.decompiler.component.DecompilerPanel`
- `ghidra.app.decompiler.DecompilerUtils`
- `docking.widgets.fieldpanel.FieldPanel`
- `docking.widgets.fieldpanel.support.FieldSelection`
- `ghidra.app.plugin.core.decompile.DecompilerProvider`

### Added APIs / imports

- `ghidra.app.decompiler.DecompilerHighlightService`
- `ghidra.app.decompiler.DecompilerHighlighter`
- `ghidra.app.decompiler.CTokenHighlightMatcher`
- `ghidra.program.model.address.AddressSet`
- `ghidra.program.model.address.AddressSetView`

---

## 3. Known issues / notes

- **Ghidra source tree**: Building against the Ghidra source tree requires that `dependencies/flatRepo/` has been populated first:
  ```
  cd /path/to/ghidra
  gradle --init-script gradle/support/fetchDependencies.gradle init
  ```
  The required modules (`Generic`, `SoftwareModeling`, `Decompiler`, `Help`, etc.) must then be built before the Cartographer build can run.

- **Binary distribution**: Building against a standard Ghidra binary release (e.g. `ghidra_12.0_PUBLIC`) works without any extra steps. Set `GHIDRA_INSTALL_DIR` to the installation directory.

- **Java version**: Java 21 is required (mandated by Ghidra 11.3+). Java 17 or earlier is not supported.

- **Gradle version**: Gradle 8.5 or later is required.
