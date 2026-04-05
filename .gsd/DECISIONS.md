# DECISIONS.md

## ADR 1: Dynamic Structure Parsing
**Date**: 2026-04-05
**Context**: We need to parse Linux memory structures.
**Decision**: We will proceed with dynamically parsing the kernel structures instead of using hardcoded architecture offsets where possible. Volatility will be referenced conceptually but not directly depended upon to meet standard-library priority goals.
**Consequences**: Increases parsing complexity but makes tool more robust across slightly differing kernel variations.
