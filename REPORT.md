# AI agent traffic in website server logs: findings from a two-week field test

Darryl Wright · 1 November 2026

## Summary

**Aim.** To record how current AI products appear in a website's server logs. To test what those logs reveal about whether an AI is acting during a visit, and whether a person or a schedule started it.

**Method.** A simple website logged requests from 18 to 31 October 2026. From 22 October it carried *lures* (short instructions addressed to AI agents), each asking for a harmless visit to a link on the same site. 105 visits from known sources were recorded: people, simple scripts, ChatGPT and Claude in several modes, and scheduled agents. Detection rules were written by an AI agent based on half these visits and tested on the rest.

**Key findings.**

- **Declared AI fetchers are easy to confirm.** ChatGPT search and Claude's fetches named themselves and came from addresses on their providers' published lists.
- **Browser-based agents are hard to spot.** ChatGPT's agent and Claude's browser agent appeared as an ordinary Chrome browser on the user's home connection. Only the absence of scrolling and typing set them apart, and some people's visits looked the same.
- **Logs did not show who started an agent.** The one visible difference was timing: scheduled tasks arrived within about 15 minutes of the same time each day.
- **Lures did not catch mainstream agents.** None of the 9 AI products and modes tested followed an openly labelled lure. Links in the lures were requested by search crawlers and link-collectors instead.
- **Rules built on these signals had limited accuracy.** On held-out test visits they gave an answer for 26 of 47, 21 of which were correct, and could not separate agents started by a person from scheduled ones.

**Conclusion.** An analyst reading a site's logs can confirm declared AI visitors against providers' address lists, but should treat ordinary browser traffic as possibly an agent, and record whether a person or a schedule started an agent's visit as unknown unless arrival times point to a schedule. Openly labelled lures placed in pages are not a reliable way to detect mainstream agents. Practical guidance is given below.

## Background

When an AI agent misbehaves on the web, investigators need to know whether a person directed it. A website operator sees only the requests that reach the server. This study tested what those requests can show.

Earlier work:

- A decoy server for remote logins (an SSH honeypot) that planted instructions for AI agents found 8 possible agents among about 8.1 million interactions over three months ([Reworr and Volkov, Palisade Research](https://arxiv.org/html/2410.13919v2)).
- Two 2026 studies told AI browsing agents from people almost perfectly in their tests, using mouse, typing and scrolling data collected by a script in the page ([Wang, Shafiq and Vekaria](https://arxiv.org/pdf/2605.01247); [Choudhary and others](https://arxiv.org/pdf/2607.26935)).
- Several groups have counted web pages that carry hidden instructions for AI ([Kaspersky](https://securelist.com/indirect-prompt-injection-in-the-wild/113295/); [Palo Alto Networks](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection.md); [Khodayari and others](https://arxiv.org/html/2604.27202v1)).

This study differed in three ways. It used what a server records. The previous studies relied on a script running in the visitor's browser, but some AI tools, such as ChatGPT search and Claude's web fetch, download a page without running any script, so only the server's records show them. It asked whether a site can tell an agent acting for a person from one acting on a schedule, which none of the studies above tested. And it tested its rules on visits held back for that purpose.

## How AI agents appeared in the logs

Observed from 22 October to 1 November 2026, from labelled visits (sessions per product in brackets). Products change often, so this is a dated reference.

| Product | Browser label (user agent) | Address | Ran the page and its files | Scrolling, pointer, typing | Requests, timing and robots.txt |
| --- | --- | --- | --- | --- | --- |
| ChatGPT search (5) | Declares `ChatGPT-User/1.0` | On OpenAI's list for fetches made at a user's request (Microsoft cloud) | No | None | 1 to 2 requests; did not read `robots.txt` |
| Claude web fetch (5) | Declares `Claude-User/1.0` | On Anthropic's single list for all its bots (Google Cloud) | No | None | 1 to 2 requests; read `robots.txt` seconds before each visit, often from a different Anthropic address |
| Claude scheduled task (9) | Same as Claude web fetch | Same as Claude web fetch | No | None | Daily between 10:20 and 10:33 UTC; read `robots.txt` seconds before each visit, often from a different Anthropic address |
| ChatGPT agent (5) | Ordinary Chrome on a Mac (version 155 or 156) | The user's home connection | Yes | Pointer only | 13 to 14 requests over 2 pages |
| ChatGPT scheduled task (9) | Same as ChatGPT agent | The user's home connection | Yes | None | 6 requests; daily between 08:56 and 09:05 UTC (8 of 9 visits) |
| Claude browser agent (5) | The user's own Chrome (version 152), identical to the person's | The user's home connection | Yes | Pointer only | 7 to 20 requests |
| Browser's built-in AI summary (5) | The user's own Chrome | The user's home connection | Yes, as part of the person's own visit | The person's own | Nothing extra reached the server |
| Author's AI agent loops (29) | `Python-urllib`, the default label of a common programming library | A cloud server, or the author's home connection | No | None | 1 request at fixed times |

Notes:

- ChatGPT's agent and scheduled task were run from the ChatGPT desktop app on the author's computer and used a different Chrome version from the author's own browser. Claude's browser agent ran in the author's own Chrome. All three therefore came from the author's home connection.
- No product sent a cryptographic signature with its requests.
- The author's loops used the same browser label as an ordinary link-following script, so they could not be told apart by label.

## Guidance for analysts

1. **Check every declared AI visitor against the provider's published address list** ([OpenAI](https://openai.com/chatgpt-user.json), [Anthropic](https://claude.com/crawling/bots.json), [Google](https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json), [Perplexity](https://www.perplexity.com/perplexity-user.json)). A match confirms the provider. A declared crawler or AI name from an address not on that provider's list is false: 73 such sessions arrived during the ten days the lures were live. In one, a visitor claiming to be Claude-User, from a Google Cloud address not on Anthropic's list, requested .env files and other secrets within five seconds. Anthropic's single list confirms the provider but not whether a visit was a crawl or a fetch for a user.
2. **Separate the scanner noise first.** Scanners rotating browser labels made over half of the sessions in the site's first 13 hours, so count by address as well as by session, or the few agent visits are lost.
3. **Do not rule out an agent behind ordinary browser traffic from a home connection.** Browser agents looked like a person's Chrome. Page activity with pointer movement but no scrolling or typing is a weak sign of an agent; some people produced the same pattern.
4. **Look at arrival times; they were the clearest sign of a scheduled agent.** ChatGPT's scheduled task arrived between 08:56 and 09:05 UTC on 8 of 9 days. Claude's arrived one to two minutes later each day, from 10:20 to 10:33 UTC. Otherwise, Claude's scheduled visits looked like its fetches made on request. ChatGPT's scheduled visits also differed from its agent (no pointer movement, one page instead of two), but with so few visits that may not hold. A person repeating a daily request could produce a similar pattern, so this is best treated as a lead. Without such a pattern, the logs could not tell whether a person or a schedule started an agent's visit.
5. **Do not rely on openly labelled lures to detect mainstream agents.** None of the 9 AI products and modes tested followed a lure. If a lure asks for an answer in a link, do not show example answers in the link: here, the lure wrote the link as `…?for_person=yes (or =no)`, and link-collectors took it only up to the space, which looked like an answer of "yes".

## Method

**The site.** webplumbingnotes.net: a home page, one short technical note, a privacy notice, `robots.txt` and `llms.txt`, on a server that did nothing else. Every request was logged: time, address, headers and the first 8 KB of any body. A small script in each page reported whether it ran and whether the visitor scrolled, moved a pointer or typed. Each day's log was sealed with a cryptographic hash (a fingerprint that changes if any byte of the file changes), so later edits would show.

**Lures.** From 22 October, lures were placed where an AI reading the site might find them: in the home page's text, placed 10,000 pixels off-screen so a person would not see it; in an HTML comment in the home page's source; in the description (alt text) of the logo image on the note page; in `llms.txt`; as a comment line in `robots.txt`; and on a public GitHub page and a public GitHub gist that linked to the site. Each lure said it was part of a research study. Every lure asked for the first of the following; the lures in the off-screen text and `llms.txt` also asked for the other two:

- visit a link with the answer to a simple sum (to show an AI read and acted on the lure);
- visit a link saying whether a person asked for the visit;
- ask the person first, then visit a link.

Each placement had its own code, so a request showed which lure was read.

**Labelled visits.** Each was logged before it started and carried its own code in the link it visited.

| Kind of visit | Visits |
| --- | --- |
| People browsing normally | 10 |
| People following the lures by hand | 5 |
| A person's browser sending a false AI label | 3 |
| A browser's built-in AI summarising the page | 5 |
| Scripts: a command-line download tool (curl), a link-following scraper, a script sending a false AI label | 15 |
| ChatGPT search, ChatGPT agent, Claude web fetch, Claude browser agent, asked by a person | 20 |
| ChatGPT and Claude scheduled tasks, daily | 18 |
| The author's own AI agent loops on timers (one using OpenAI's gpt-4o-mini through its API, one using the open-weight gpt-oss:20b on the author's computer) | 29 |
| Total | 105 |

A **session** is all requests from one address with the same browser label (user agent), with no gap over 30 minutes. The table counts sessions.

**What the rules could use.** For each session: whether it declared an AI name; whether its address was on an AI company's published list; the type of network (hosting company, privacy relay or other); whether the page script ran; scrolling, pointer and typing; whether `robots.txt` was read first; whether it followed a lure; the number of requests and the time between pages; and on how many days the same visitor returned. Addresses, browser labels and times were not available to the rules.

**How the rules were made and tested.**

1. The labelled sessions were split 58 for writing the rules, 47 for the test, stratified by visit type.
2. A separate AI agent (Claude), with no access to the rest of the project, wrote the rules from the 58 sessions and the study's definitions. A "cannot tell" answer was allowed when the evidence was unclear.
3. The rules were checked for coding errors (one was fixed). Their cryptographic hash was then posted publicly, before the test.
4. The 47 test sessions were scored once.

**Score.** Balanced accuracy was used to score the rules' performance and calculated both including "cannot tell" as incorrect, and leaving those sessions out.

The method, signals and lure wording were fixed before the lures went live. Changes made during collection and analysis are listed, with reasons, in the study protocol in the repository.

## Results

**Test scores**

| Task | Test sessions | Balanced accuracy, "cannot tell" included | Balanced accuracy, "cannot tell" excluded | Answered "cannot tell" |
| --- | --- | --- | --- | --- |
| AI acting during the visit, or not | 47 | 0.52 | 0.81 | 45% |
| Agent started by a person, or by a schedule | 30 agent sessions | 0.13 | 1.00 (2 answers) | 93% |

On the 58 sessions used to write them, the rules scored 0.65 (0.88) with "cannot tell" included (excluded) on the first task. Declared fetchers and scripts were correctly recognised, browser agents were recognised only when no one scrolled or typed, and nothing in the signals separated agents started by a person from scheduled ones.

**How agents handled the lures.** None of the 9 AI products and modes tested (ChatGPT search, agent and scheduled task; Claude web fetch, browser agent and scheduled task; a browser's built-in AI summary; the author's two agent loops, using gpt-4o-mini and gpt-oss:20b; 72 sessions in all) followed a lure, reported itself or asked its user. Claude's fetcher read `robots.txt`, which carried a lure, seconds before 14 of its 15 visits in the lure period, and did not act on it. Nothing in the study read llms.txt except the author by hand, a web-data crawler and a few visitors with ordinary browser labels. The author's two loops did see them: the lure text reached the model in 28 of 29 sessions, and most final summaries described it as a note for AI agents (gpt-oss also worked out the sum), yet neither loop requested a lure link. The products' saved answers show most of them saw the lures too. A lure was mentioned in 5 of 5 ChatGPT search answers, 4 of 5 Claude web fetch answers, 3 of 5 ChatGPT agent answers, 1 of 5 Claude browser agent answers and none of the 5 browser AI summaries. Several answers said the page held instructions for AI and that they had not acted on them.

**Unknown visitors.** Outside the labelled visits, 2,385 sessions arrived before the lures went live and 8,420 while they were live, about two thirds from hosting companies in both periods. 23 sessions requested a lure's link: Google's, Bing's and Baidu's crawlers, a cloud network sending a phone browser label, a browser run by a program without a screen, and a link-collector. None answered the sum or paused. Five appeared to report that a person had asked for the visit, but this was an artefact of the lure design: the link was written as `…?for_person=yes (or =no)&model=…`, and link-collectors took the link only up to the space, producing "yes". No AI agent was identified among unknown visitors.

## Lessons for building a similar sensor

Four design problems limited what this sensor could show. Each applies to any similar study.

1. **Agents that run in the user's own browser look like the user.** ChatGPT's agent and scheduled task, and Claude's browser agent, ran in a browser on the author's computer. Their address and network were the author's home connection, so the network signals that identify AI companies' traffic did not apply.
2. **An address list that covers several roles cannot separate them.** Anthropic publishes one list for its crawler and its fetches made for users. A visit from that list can be confirmed as Anthropic's, but not as a crawl or as a fetch for a person. OpenAI publishes separate lists, and its fetches for users were identified correctly.
3. **Behaviour signals need a page that invites behaviour, and enough examples.** The pages were short, so people had little reason to scroll. The rules were written from only 4 sessions of people browsing, and all four had scrolled or typed, so "no scrolling or typing" looked like a reliable sign of an AI. In the test, three of nine people's visits had neither.
4. **Links written in a lure can be collected by ordinary crawlers.** Crawlers that extract links from page text requested the lures' links without reading them. Because the self-report link included an example answer, they produced false "yes" reports.

## Future work

- **Longer pages.** Use pages long enough to need scrolling.
- **Agents running in a provider's own cloud browser as well as on users' computers,** recorded as separate kinds of visit. OpenAI [documents a cloud browser for ChatGPT](https://help.openai.com/en/articles/11845367-chatgpt-agent-allowlisting) that signs its requests; the ChatGPT agent runs in this study came from the author's computer and were not signed.
- **Visit timing as a sign of a schedule.** Visits at the same time each day separated scheduled agents from requests by a person in this study (though this was not used in developing the rules), but it seems a brittle signal easily confounded by other human or agent behaviour.
- **Lure links that a link-collector cannot complete.** Give no example values in the link, and require a value that only a reader of the lure would know.
- **Lure links that serve the agent's task.** The author's loops saw the lures and reported them to their user but did not act on them. Put part of the page's content behind a lure link, so an agent follows it because its task needs the content, not because it was told to. The lure stays openly labelled.
- **Lures in visible page text.** The browser's AI summary never mentioned a lure and Claude's browser agent did so once, so they may not have seen the hidden ones. Visible lures would show whether they ignore them or never see them.
- **More AI products,** including Perplexity and Google's agent, whose providers publish separate address lists by role.
- **The planned tests not run here:** a human making visits whose labels are kept from the analyst, and a deliberate attempt to defeat the rules.
- **Several sites over several months,** to measure how often each kind of visitor occurs, not only whether it can be recognised.

## Limits

- **Small and short.** One new website with no inbound links, over two weeks.
- **Few labelled visits.** About 5 per kind of visit; one unusual visit could change results noticeably.
- **Built stand-ins for autonomous agents.** The scheduled examples were two products' scheduled tasks and the author's own loops. Agents in the wild may behave differently.
- **The lures said they were part of a study.** Agents may treat such lures differently from hidden instructions.
- **One rule writer.** Another set of rules might have done better or worse with the same signals.

## Data, code and records

- **Code, study protocol and results:** [github.com/dr-darryl-wright/ai-agent-web-sensor](https://github.com/dr-darryl-wright/ai-agent-web-sensor). The protocol (`PREREGISTRATION.md`) lists the eleven changes made during collection and analysis, each with its reason.
- **Fixed in advance:** the method, signals and lure wording on 19 October 2026 at 18:46:56 UTC (SHA-256 `13702beb7990a2c10c86ce2680f66425386809e40cd6e908cbf66ce4b0821171`); the detection rules on 1 November 2026 at 19:54:40 UTC (SHA-256 `69b7db41d9400de9e3a646ecf9bf0da96e52f5274d35e64874ccb83a47649f19`), posted publicly at 20:06 UTC in a [GitHub gist](https://gist.github.com/dr-darryl-wright/d311041f80e554f5dd127e1f2e50e4da), before the test was run at 20:08 UTC.
- **Personal data:** visitors' IP addresses are not published. Raw logs are kept privately and deleted on 31 January 2027. The site carried a privacy notice describing the study.
- **Tools used:** Claude (Anthropic) was used as an engineering and drafting assistant, and a separate Claude agent wrote the detection rules. Design decisions and checks were the author's.

## Sources

- [Reworr and Volkov, LLM Agent Honeypot: Monitoring AI Hacking Agents in the Wild (arXiv 2410.13919)](https://arxiv.org/html/2410.13919v2)
- [Wang, Shafiq and Vekaria, FP-Agent: Fingerprinting AI Browsing Agents (arXiv 2605.01247)](https://arxiv.org/pdf/2605.01247)
- [Choudhary and others, What Does It Take to Detect an AI Agent? (arXiv 2607.26935)](https://arxiv.org/pdf/2607.26935)
- [Kaspersky, Indirect prompt injection in the wild (2024)](https://securelist.com/indirect-prompt-injection-in-the-wild/113295/)
- [Palo Alto Networks Unit 42, Web-Based Indirect Prompt Injection Observed in the Wild (2026)](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection.md)
- [Khodayari, Zhang, Pellegrino and Acharya, Indirect Prompt Injection in the Wild (arXiv 2604.27202)](https://arxiv.org/html/2604.27202v1)
- [Anthropic crawler address list](https://claude.com/crawling/bots.json)
