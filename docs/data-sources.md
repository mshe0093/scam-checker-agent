# Data sources

Where the rules engine's knowledge comes from, and how it was checked. Every contact and scam template
in `src/scamcheck/data/` also carries its own `source_url`.

## Organisations and official domains (`official_orgs.json`)

**53 organisations:**
- every consumer-facing bank, Islamic bank, digital bank and development bank on Bank Negara's register
  that scammers are likely to impersonate
- the main e-wallets
- government agencies
- couriers, telcos, utilities and marketplaces

**Where the list of institutions comes from.** Banks, digital banks, development financial institutions
and e-money issuers come from Bank Negara Malaysia's
[Financial Sector Participants Directory](https://www.bnm.gov.my/regulations/fsp-directory), read on 2026-11-08.

**How the domains were checked (2026-11-08).** A domain counts as official only if one of these is true:

1. Its homepage loaded over HTTPS and the page title named the institution. For example, `affinalways.com`
   is titled "Affin Bank" and `kafdigitalbank.com.my` is titled "KAF Digital Bank".
2. For `.my` domains that don't serve a site: a MYNIC WHOIS record shows a long-held, locked registration.
   That applies to `affinbank.com.my` (registered 1996), `rhbbank.com.my` (2003) and `maybank.com.my` (1998).

**Left out on purpose:**

| Left out | Why |
|---|---|
| `mae.com.my` | It's an English-learning site, not Maybank's MAE app. Listing it would whitelist a domain Maybank doesn't own |
| `pbislamic.com.my` | Not registered, so anyone could buy it |
| SME Bank, Citibank, ICBC, Merchantrade, Public Islamic's separate domain | The homepage couldn't be confirmed: it was behind a bot check, timed out or wouldn't load. They can be added once someone confirms the domain |
| Wholesale-only banks (BNP Paribas, Deutsche Bank, J.P. Morgan, Mizuho, MUFG, SMBC, Bank of America) | They have no retail customers, so they're rarely impersonated |
| Short or common-word brand tokens (`grab`, `digi`, `boost`, `mudah`, `uob`, `kfh`) | They would match unrelated domains like `photograbber.com` or `pinjamanmudah.com`. These organisations are still detected by name in the message |

**Hotlines.** These only come from the organisation's own page (`official_page`) or reputable
reporting (`secondary_source`). The source URL is stored with each one.

## Scam tactics (`tactics.json`) and templates (`scam_patterns.json`)

These are based on police, regulator and news reports of scams in Malaysia. The main sources:

| Scam | Source |
|---|---|
| Overall picture: telecommunications and investment scams cause the biggest losses, followed by e-commerce, loans and love scams | [Business Today, 2026-06-15](https://www.businesstoday.com.my/2026/06/15/online-scam-losses-surge-to-rm2-97-billion-in-2025/) |
| `.apk` wedding invitations | [Bukit Aman via The Vibes](https://www.thevibes.com/articles/news/102258/beware-of-wedding-invites-carrying-malware-says-bukit-aman) |
| WhatsApp 6-digit code hijacking | [CelcomDigi](https://help.celcomdigi.com/support/solutions/articles/70000654932-fake-6-digit-verification-codes-scam-on-whatsapp) |
| Macau scam, "safe account" | [SAYS on PDRM's warning](https://says.com/my/news/pdrm-warns-public-to-be-wary-of-telecommunication-fraud-macau-scam) |
| Bank-account rental (mules) | [The Star, 2026-01-30](https://www.thestar.com.my/news/nation/2026/01/30/dont-fall-for-bank-account-rental-scam-warns-johor-mca-youth) |
| "Easy" part-time task jobs | [The Star, 2026-04-07](https://www.thestar.com.my/news/nation/2026/04/07/easy-part-time-jobs-now-top-tactic-in-online-scam-wave-says-bukit-aman) |
| Fake NSRC officers | [The Sun](https://thesun.my/news/malaysia-news/police-receive-23-reports-of-bogus-nsrc-officers-involving-over-rm700000-in-losses-an11857447/) |
| Fake fund recovery ("double scam") | [Malay Mail, 2026-04-13](https://www.malaymail.com/news/malaysia/2026/04/13/pay-more-lose-more-police-warn-of-double-scam-trapping-victims-with-fake-recovery-offers/216147) |
| Deepfake officials and celebrities promoting investments | [BNM and SC warning via The Vibes](https://www.thevibes.com/articles/news/128334/bnm-sc-warn-of-deepfake-videos-using-senior-officials-to-promote-investment-scams) |
| QR code scams | [The Star, 2026-09-03](https://www.thestar.com.my/news/nation/2026/09/03/watch-out-for-scan-artists-public-urged) |
| COD parcel scams | [The Star, 2026-03-09](https://www.thestar.com.my/news/nation/2026/03/09/beware-of-cod-parcel-scams-on-whatsapp-public-told) |
| Rental scams | [The Vibes](https://www.thevibes.com/articles/news/118093/fraudulent-property-rental-scams-surge-in-malaysia-amid-rising-identity-theft-police) |
| Love scams | [Bernama](https://bernama.com/en/crime_courts/news.php?id=2526281) |
| TNB overdue-bill SMS | [The Star fact check](https://www.thestar.com.my/news/true-or-not/2024/11/15/quickcheck-does-a-utility-company-send-smses-with-links-to-customers-with-overdue-bills) |
| KWSP/EPF | [Malay Mail](https://www.malaymail.com/news/malaysia/2017/06/15/epf-warns-members-of-false-messages-and-scams-on-social-media/1399903) |
| STR/SARA aid | [Malay Mail, 2025-05-05](https://www.malaymail.com/amp/news/malaysia/2025/05/05/only-trust-govmy-sites-for-sumbangan-tunai-rahmah-updates-teo-warns-as-scam-links-spread/175632) |

All templates and test messages are self-written paraphrases. No advisory or news text is copied.

## Re-checking

Domains and hotlines change. Before relying on the dataset, re-check the domains (load each homepage
and confirm the title names the institution), and update `_meta.checked_on` in `official_orgs.json`.
