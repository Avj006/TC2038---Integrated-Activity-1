# TC2038 - Integrated Activity 1.2: Transmission Analysis Tool

A C++ tool for analyzing hexadecimal-encoded transmissions, developed as part of Integrated Activity 1 (Problem Situation 1) for the TC2038.601 course.

## Authors

- Angela Andrea Castro García — A01640019
- Andrea Villaseñor Jiménez — A01642088

## Description

The program reads five fixed-name text files (not requested from the user) containing exclusively hexadecimal characters (0-9, A-F) and line breaks:

- `transmission1.txt`
- `transmission2.txt`
- `mcode1.txt`
- `mcode2.txt`
- `mcode3.txt`

Transmission files simulate data sent between devices. The `mcodeX.txt` files represent malicious code sequences that may be hidden inside a transmission. The program performs three independent analyses:

1. **Part 1 — Malicious Code Pattern Matching (KMP Algorithm):** For each of the two transmissions, checks whether each of the three malicious codes (`mcode1`, `mcode2`, `mcode3`) is contained within it. Prints `true <position>` (1-indexed starting position) if found, or `false` otherwise — 6 lines total.
2. **Part 2 — Longest "Mirrored" / Palindromic Substring (Manacher's Algorithm):** For each transmission, finds the longest palindromic substring at the character level and prints its `startPosition endPosition` (1-indexed) — 2 lines total.
3. **Part 3 — Longest Common Substring (Dynamic Programming):** Finds the longest substring shared between `transmission1.txt` and `transmission2.txt`, and prints its `startPosition endPosition` (1-indexed), relative to `transmission1.txt` — 1 line.

## Submission (.ZIP) Folder Structure

Per the activity instructions, the deliverable is a single `.zip` file, submitted by one team member, following this exact hierarchy: