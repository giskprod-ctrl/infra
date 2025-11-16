// Place allow/deny overrides and helper rules in this file.
// Example of suppressing an overly noisy rule:
// private rule INTERNAL_Suppress_GenericDropper { condition: GENERIC_Dropper }
// This rule file is included after all primary categories so overrides take precedence.

private rule INTERNAL_NoOverrides
{
    meta:
        description = "Placeholder rule to keep the file non-empty"
        scope = "internal/override"
    condition:
        false
}
