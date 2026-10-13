# Teaching With OpenVAPT

Version 1.0, effective 2026-10-13. These are the authoritative terms for teaching with OpenVAPT. They form part of the OpenVAPT Source-Available Licence 1.1 (section 2, "Teaching") and the End User Licence Agreement. They were drafted by an AI Cybersecurity Engineer and reviewed by a separate AI system acting as the project's legal reviewer; no human lawyer drafted or reviewed them. They are not legal advice.

OpenVAPT is academic, non-commercial, source-available code built by AI Cybersecurity Engineers, free to use and used 100% at your own risk. Teachers are welcome to use it. These terms say exactly how.

## 1. Who May Teach With OpenVAPT

Teaching is allowed for:

1. Schools, colleges, universities, polytechnics and other educational institutions, including those that charge ordinary tuition or course fees for their general programmes.
2. Government training academies and public sector training bodies teaching their own staff or students.
3. An organisation training its own employees internally, on machines it owns or controls. This is also Own Use.
4. Individual teachers, tutors and study groups teaching free of charge.

Teaching is not allowed, and is a Service under the licence, for:

1. Commercial training providers, whose business is selling training.
2. Paid bootcamps, workshops or courses sold to the public.
3. Certification courses, exam preparation or certificates sold for a fee.
4. Training the staff of another organisation, paid or unpaid.
5. Any course, module or material where a fee, or any other payment, is charged specifically for OpenVAPT or for teaching about it.

Ordinary tuition is fine. A fee for OpenVAPT is not.

## 2. Teaching Materials

You may copy, adapt, shorten, translate and rearrange the OpenVAPT Academy modules, quizzes, worksheets, rubrics, course plans, glossary and documentation into your own slides, handouts, exams and learning management system, for your own students, free of charge. Every copy or adaptation must:

1. Credit the source: "Adapted from the OpenVAPT Academy (openvapt.com), built by AI Cybersecurity Engineers, used under the OpenVAPT Source-Available Licence 1.1."
2. Carry this notice: "OpenVAPT is not affiliated with, and is not endorsed by, this institution or any third party named in this material. Pre-release versions may be wrong or unstable. Use at your own risk."
3. Say clearly where you changed the material.

You may not sell the materials, publish them as a paid product, or present them as approved, certified or endorsed by OpenVAPT. You remain responsible for checking that the material is accurate before you teach it; it was built by AI Cybersecurity Engineers and may contain mistakes.

## 3. Where Students May Run OpenVAPT

1. **The simulated lab.** `openvapt demo` and the website Academy run anywhere and touch no real machine. This is always allowed and is the recommended starting point.
2. **Institution lab machines and virtual machines.** Computers, servers and virtual machines that the institution owns or controls, including virtual machines on institution infrastructure that are given to students, count as machines the institution owns or controls. Students may run OpenVAPT on them under the teacher's supervision, when the institution has authorised it.
3. **A student's own machine.** A student may run OpenVAPT on a computer the student personally owns or controls, as the student's own Own Use and not as Teaching, after accepting the terms personally (or through a parent or guardian if under 18, section 6). The teacher must not run it on a student's machine for them, and a class assignment must not require a student to run it on their own machine.
4. **Nowhere else.** No class may run OpenVAPT, or use anything learned from it, against any machine, network or website belonging to anyone else, including volunteers, family, employers or the public internet.

## 4. Remote, Recorded and Online Teaching

Live online classes, recorded lectures, screen recordings of `openvapt demo` and free open online courses (MOOCs) are allowed. A recording or online course must show the notice in section 2 and must not charge a fee for OpenVAPT content. An online course that charges for a certificate based on OpenVAPT content is not allowed. Never show real reports, hostnames, secrets or personal data on screen.

## 5. Assessment, Projects and Competitions

Grading, quizzes, exams, coursework, student projects, theses and dissertations, and competitions and capture-the-flag style exercises are allowed, but only on the simulated lab or on institution machines under section 3.2. Competitions must be free to enter, must not award prizes funded by selling OpenVAPT, and must never include any target outside the institution's own machines. A student may cite OpenVAPT in academic work (see CITATION.cff). Grades and certificates are issued by the institution, never by or on behalf of OpenVAPT.

## 6. Students Under 18

Students under 18 (or under the age of majority where they live, if higher) may download or run OpenVAPT only after a parent or guardian has accepted the EULA for them. Without that acceptance, they may use only the website Academy and watch the teacher's demonstration, without downloading anything.

## 7. How Students Accept the Terms

1. Each student who downloads, builds or runs OpenVAPT must read and accept the acknowledgements personally, on the website or by typing `I ACCEPT` in the tool.
2. The teacher must not accept for a student, must not tell students to use `--accept-terms`, and must not set up any shared machine that accepts for them.
3. A class may use only the website Academy and the teacher's own projector demonstration, without each student downloading. In that case only the teacher accepts.

## 8. The Teacher's Checklist

Before a class runs OpenVAPT on any real machine, the teacher must:

1. **Get authorisation** in writing, or by the institution's normal process, from the person responsible for the lab machines or virtual machines.
2. **Isolate the lab.** Use machines and virtual machines that are separated from production systems and contain no real personal data or secrets.
3. **Use no third-party targets.** Make sure no student runs it on, or aims anything at, a machine the institution does not own or control.
4. **Brief ethics and law.** Explain that accessing a computer without authorisation is an offence under Malaysia's Computer Crimes Act 1997, and that similar laws apply elsewhere, and that authorisation must come from the owner of the machine.
5. **Check every student has accepted** personally, or has a parent's or guardian's acceptance if under 18.
6. **Preview first** with `openvapt scan --dry-run`, and tell students that reports describe weaknesses and must not be shared outside the class.
7. **Explain the limits.** Results may be wrong or incomplete, pre-release builds may be unstable, and a clean report does not prove a system is secure.

## 9. Responsibility

The teacher and the institution are responsible for how OpenVAPT is used in their teaching. OpenVAPT is given free, as is, with no warranty and no support, and the EULA's exclusions, release and indemnity apply to teachers, institutions and students alike. Nothing in these terms creates any relationship between OpenVAPT and any institution.

## 10. Changes

These terms may be updated. Each version is dated and kept in the public Git history. The version provided with your copy of OpenVAPT applies to that copy.
