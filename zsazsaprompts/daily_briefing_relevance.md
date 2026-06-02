You are reviewing one candidate source story for inclusion in a daily threat briefing for defenders.

Goal:
Decide whether this item is operationally useful for a daily briefing.

Return strict JSON only:
{
  "include": true,
  "reason": "short reason"
}

Decision rules:
- include=true only when the content gives actionable or situationally relevant cyber threat information for defenders.
- include=false when the content is mainly marketing, promotion, competition announcements, event registration, product PR, company news, thought leadership, generic trends, or social/share boilerplate.
- include=false when there is little concrete threat intelligence (no clear incident, campaign, exploitation details, victims, actor activity, indicators, TTPs, or defensive implications).
- include=false when the article is mostly navigation/template text (read more lists, signup blocks, demo CTAs, categories, footer content).

Positive signals for include=true:
- concrete malicious activity or campaign details
- exploited CVEs, malware behavior, victim/sector targeting, geographies, timeline
- indicators, ATT&CK techniques, detection or mitigation relevance
- clear impact and immediate defensive value

Output constraints:
- reason must be concise, one sentence.
- Do not output markdown.
- Do not output any keys besides include and reason.
