You are checking drafted daily-briefing stories for duplicate coverage of the same real-world event.

Task:
- Compare all stories pairwise.
- Identify pairs that likely describe the same underlying incident or campaign.
- Focus on event identity, not topic similarity alone.
- A story pair is overlap when they share key event facts such as: same victim/organization, actor/group, malware family, CVE chain, date/time window, IOC cluster, or same operation name.
- Do not mark overlap if one story is clearly broader context and the other is a distinct event.

Output must be strict JSON only, no markdown:
{
  "summary": "short operator note",
  "overlaps": [
    {"a": 1, "b": 3, "score": 0.87, "reason": "Both describe the same ransomware intrusion at Org X on the same date with matching actor and TTPs."}
  ]
}

Rules:
- Indices a and b are 1-based story indexes from input.
- score range is 0.0 to 1.0 where 1.0 means near-certain duplicate event.
- Keep overlaps list empty when no meaningful duplicates are found.
- Prefer precision over recall. Avoid weak guesses.
