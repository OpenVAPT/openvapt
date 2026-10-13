# Citing OpenVAPT

Version 1.1, effective 2026-10-14 (1.0 was dated 2026-10-13; 1.1 refers to licence 1.3 and changes no guidance). This is the canonical guide to crediting and citing OpenVAPT. It was drafted by a separate AI system acting as the project's legal reviewer; no human lawyer drafted or reviewed it. It is not legal advice. The machine-readable version is `CITATION.cff`.

**Please cite us.** If OpenVAPT, its Academy, its documentation, its checks or its reports helped your work in any way, in a research paper, thesis, dissertation, coursework, assignment, presentation, poster, academic project, teaching material, book, article, blog post or video, please cite OpenVAPT. Copy any format below and fill in the version you used.

## 1. When You Must Credit, and When We Ask You to Cite

There are two layers.

**Required (licence condition).** Section 5.4 of the OpenVAPT Source-Available Licence 1.3 (`LICENSE`) requires Credit whenever you copy, quote, share, translate, adapt or present any OpenVAPT Material, in whole or in part, in any medium. OpenVAPT Material means the parts of OpenVAPT protected by copyright: source code, documentation, Academy modules, quizzes, worksheets, rubrics, course plans, glossary, check descriptions, report templates, website text, figures, diagrams and screenshots. Credit must:

1. name "OpenVAPT";
2. give https://openvapt.com or https://github.com/OpenVAPT/openvapt;
3. give the version used, where you know it;
4. say "adapted from" or "translated from" where you changed the material; and
5. not suggest that OpenVAPT sponsors, endorses, approves or has reviewed your work.

Any citation below satisfies these items. Give Credit in the way that suits the medium: reference list, slide, speaker notes, caption, footer, file header comment, or aloud. If it is impractical at the point of use, give it at the first practical place.

**Requested (not a licence condition).** We also ask you to cite OpenVAPT when you only ran the tool, used its findings, or used ideas, methods or knowledge you learned from it without copying its words, code or figures. The law does not let a licence require citation for ideas, facts or methods, and nothing here limits fair dealing under the Copyright Act 1987 or any other right the law gives you. But academic integrity rules at almost every university and journal require you to acknowledge the tools and sources you used, so citing OpenVAPT is usually expected of you anyway.

| Your use | Credit required? | Citation requested? |
|---|---|---|
| Quoting text, code or a check description in a paper, thesis or report | Yes | Yes |
| Using an OpenVAPT figure, diagram or screenshot in slides or a poster | Yes | Yes |
| Adapting Academy modules, quizzes or worksheets for a class (also follow `TEACHING.md` section 2) | Yes | Yes |
| Copying or adapting source code into your own project | Yes | Yes |
| Running OpenVAPT and reporting your results in coursework or research | No | Yes |
| Learning a concept from the Academy and explaining it in your own words | No | Yes |
| Running OpenVAPT privately on your own machine | No | Welcome |

## 2. What to Cite

| You used | Cite | Add |
|---|---|---|
| The software (tool, scanner, report signing) | The software reference (section 3) | The exact version, for example 0.1.0-alpha.2 |
| A specific build or unreleased code | The software reference | The Git commit (section 4) |
| The Academy as a whole | The Academy reference (section 5) | The date you accessed it |
| One Academy module, worksheet or page | The page reference (section 5) | The module title, web address and date accessed |
| One check (for example HOST-SSH-001) | The software reference | The check ID in your text, for example "check HOST-SSH-001 of OpenVAPT 0.1.0-alpha.2 (OpenVAPT, 2026)" |
| A report produced by OpenVAPT | The software reference | The version that produced the report, shown in the report |
| The documentation or website text | The page reference (section 5) | The web address and date accessed |

**Author.** The author is the project: "OpenVAPT". Do not add personal names. OpenVAPT is built by AI Cybersecurity Engineers under the direction of the project owner; if your style or institution asks how the work was made, you may add the note "Built by AI Cybersecurity Engineers". Treat "OpenVAPT" as a group author, so reference managers must not split it into a first and last name (in BibTeX it is wrapped in double braces for this reason).

**Year and version.** Use the year of the version you used (2026 for every current version) and the version shown by `openvapt version` or on the release page. Pre-release versions (alpha, beta, rc) are fine to cite; give the full version string.

**Date accessed.** For web pages and the Academy, which can change, give the date you accessed them.

## 3. Citing the Software

Replace `0.1.0-alpha.2` with the version you used. All formats below describe the same work.

**APA 7**

```
OpenVAPT. (2026). OpenVAPT: An open academic vulnerability assessment tool (Version 0.1.0-alpha.2) [Computer software]. https://github.com/OpenVAPT/openvapt
```

In text: (OpenVAPT, 2026)

**IEEE**

```
OpenVAPT, "OpenVAPT: An Open Academic Vulnerability Assessment Tool," version 0.1.0-alpha.2, 2026. [Online]. Available: https://github.com/OpenVAPT/openvapt
```

**Harvard**

```
OpenVAPT (2026) OpenVAPT: An Open Academic Vulnerability Assessment Tool. Version 0.1.0-alpha.2 [Computer program]. Available at: https://github.com/OpenVAPT/openvapt (Accessed: 13 October 2026).
```

In text: (OpenVAPT, 2026)

**MLA 9**

```
OpenVAPT. OpenVAPT: An Open Academic Vulnerability Assessment Tool. Version 0.1.0-alpha.2, 2026. GitHub, github.com/OpenVAPT/openvapt.
```

In text: (OpenVAPT)

**Chicago (17th edition, author-date)**

```
OpenVAPT. 2026. OpenVAPT: An Open Academic Vulnerability Assessment Tool. Version 0.1.0-alpha.2. Computer software. https://github.com/OpenVAPT/openvapt.
```

**Vancouver**

```
OpenVAPT. OpenVAPT: an open academic vulnerability assessment tool [Internet]. Version 0.1.0-alpha.2. 2026 [cited 2026 Oct 13]. Available from: https://github.com/OpenVAPT/openvapt
```

**BibTeX (@software, for biblatex or modern styles)**

```bibtex
@software{openvapt_2026,
  author       = {{OpenVAPT}},
  title        = {{OpenVAPT: An Open Academic Vulnerability Assessment Tool}},
  year         = {2026},
  version      = {0.1.0-alpha.2},
  url          = {https://github.com/OpenVAPT/openvapt},
  note         = {Built by AI Cybersecurity Engineers. https://openvapt.com},
  license      = {LicenseRef-OpenVAPT-SAL-1.3}
}
```

**BibTeX (@misc, for classic BibTeX styles that do not know @software)**

```bibtex
@misc{openvapt_2026,
  author       = {{OpenVAPT}},
  title        = {{OpenVAPT: An Open Academic Vulnerability Assessment Tool}},
  year         = {2026},
  howpublished = {\url{https://github.com/OpenVAPT/openvapt}},
  note         = {Computer software, version 0.1.0-alpha.2. Accessed 13 October 2026}
}
```

**BibLaTeX**

```bibtex
@software{openvapt_2026,
  author       = {{OpenVAPT}},
  title        = {OpenVAPT: An Open Academic Vulnerability Assessment Tool},
  date         = {2026},
  version      = {0.1.0-alpha.2},
  url          = {https://github.com/OpenVAPT/openvapt},
  urldate      = {2026-10-13},
  organization = {OpenVAPT},
  addendum     = {Built by AI Cybersecurity Engineers}
}
```

**RIS (EndNote, Zotero, Mendeley)**

```
TY  - COMP
AU  - OpenVAPT
TI  - OpenVAPT: An Open Academic Vulnerability Assessment Tool
PY  - 2026
ET  - 0.1.0-alpha.2
UR  - https://github.com/OpenVAPT/openvapt
N1  - Built by AI Cybersecurity Engineers. https://openvapt.com
ER  - 
```

**CSL-JSON (Zotero, Pandoc)**

```json
[
  {
    "id": "openvapt_2026",
    "type": "software",
    "author": [{ "literal": "OpenVAPT" }],
    "title": "OpenVAPT: An Open Academic Vulnerability Assessment Tool",
    "version": "0.1.0-alpha.2",
    "issued": { "date-parts": [[2026]] },
    "URL": "https://github.com/OpenVAPT/openvapt",
    "note": "Built by AI Cybersecurity Engineers"
  }
]
```

**Plain text**

```
OpenVAPT (2026). OpenVAPT: An Open Academic Vulnerability Assessment Tool, version 0.1.0-alpha.2. Built by AI Cybersecurity Engineers. https://openvapt.com
```

GitHub also reads `CITATION.cff` and shows a "Cite this repository" button with APA and BibTeX.

## 4. Citing a Specific Commit

For unreleased code, or to make your work exactly reproducible, add the commit. Get it with `git rev-parse HEAD`, or from the footer of the website ("Built ... from commit").

```
OpenVAPT. (2026). OpenVAPT: An open academic vulnerability assessment tool (Version 0.1.0-alpha.2, commit <first 12 characters of the commit>) [Computer software]. https://github.com/OpenVAPT/openvapt/tree/<full commit>
```

In BibTeX or BibLaTeX, add `commit = {<full commit>}` (biblatex-software) or put it in `note`.

## 5. Citing the Academy, a Module or a Web Page

**The Academy (APA 7)**

```
OpenVAPT. (2026). OpenVAPT Academy [Online course]. Retrieved October 13, 2026, from https://openvapt.com/academy/
```

**One module or page (APA 7)**

```
OpenVAPT. (2026). <Module or page title>. OpenVAPT Academy. Retrieved <Month Day, Year>, from <web address of the page>
```

**One module or page (IEEE)**

```
OpenVAPT, "<Module or page title>," OpenVAPT Academy, 2026. [Online]. Available: <web address of the page>. [Accessed: <Day Mon. Year>].
```

**One module or page (Harvard)**

```
OpenVAPT (2026) <Module or page title>. OpenVAPT Academy. Available at: <web address of the page> (Accessed: <Day Month Year>).
```

For other styles, use the software format with the page title and web address, and add the date accessed.

## 6. Short Credit Lines

Use these where a full reference does not fit. Add the full reference to your reference list, description or handout where there is one.

**Slide, poster or figure caption**

```
Source: OpenVAPT 0.1.0-alpha.2, openvapt.com
```

**Adapted figure, table or text**

```
Adapted from OpenVAPT (openvapt.com), version 0.1.0-alpha.2, under the OpenVAPT Source-Available Licence 1.3.
```

**Adapted teaching material** (exact wording required by `TEACHING.md` section 2)

```
Adapted from the OpenVAPT Academy (openvapt.com), built by AI Cybersecurity Engineers, used under the OpenVAPT Source-Available Licence 1.3.
```

**Spoken (video, talk or podcast)**

```
This uses OpenVAPT, an academic vulnerability assessment tool from openvapt.com.
```

**Acknowledgements section of a thesis or paper**

```
This work used OpenVAPT (version 0.1.0-alpha.2, https://openvapt.com), an academic vulnerability assessment tool built by AI Cybersecurity Engineers.
```

**In source code** (at the top of any file that contains copied or adapted OpenVAPT code)

```
// Contains code adapted from OpenVAPT (https://github.com/OpenVAPT/openvapt), version 0.1.0-alpha.2,
// Copyright (c) 2026 OpenVAPT and contributors, used under the OpenVAPT Source-Available Licence 1.3
// (LicenseRef-OpenVAPT-SAL-1.3). Modified.
```

Use the comment syntax of your language (`#` for shell and Python). Remove the word "Modified." only if you changed nothing. Copied code must still keep every `Required Notice:` line (licence section 5.2), and copying code is permitted only within the licence (Own Use, contribution, Teaching or free sharing).

## 7. What Citing Does Not Do

Citing OpenVAPT does not give you any permission the licence does not give, and it does not mean OpenVAPT endorses, approves or has reviewed your work. Do not describe your work as certified, audited or approved by OpenVAPT. OpenVAPT findings are not a professional assessment; describe them as results from an academic tool, used at your own risk.

## 8. Changes

This guide may be updated. Each version is dated and kept in the public Git history. Version history: 1.0 (2026-10-13) first version.
