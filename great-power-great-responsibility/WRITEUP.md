# Great Power, Great Responsibility — CTF Writeup

**Category:** WEB + OSINT  
**Points:** 200  
**Flag Format:** `iCS{}` / `ICS{}` / `ics{}`

## Challenge Description

> Mr. Manduka Rapatulo is a clerk at Chameleo International. Mr. Manduka is a Chill millennial who likes to hang out with friends and have his **snap time**.
> You will find the secret, where the **power is at its peak**.

**URL:** https://chameleo-great-power-zcgb4f64hq-el.a.run.app/culture

---

## Reconnaissance

### Site Pages
- `/culture` - Company culture page
- `/team` - Employee directory
- `/login` - Employee login portal
- `/ceo/employees/search` - CEO-level employee search API

### Key Clues
- "snap time" - Snapchat OSINT
- "where the power is at its peak" - CEO role / `/ceo/` endpoint
- `/ceo/employees/search?source=employees&fields=id,full_name,department,role,email,branch&q=`

---

## Investigation Steps

*(to be filled)*

---

## Flag

`iCS{...}`
