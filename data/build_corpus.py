"""Generate the synthetic labelled evidence corpus.

Every message here is fabricated for testing. The organisation
(northwind-logistics.com), its staff, its vendors and the attacker
infrastructure are all invented; no real mailbox, person or domain is
represented. Regenerate with:

    python data/build_corpus.py

Labels in `labels.json` are the ground truth used by tests/test_validation.py
to measure detection performance.
"""

from __future__ import annotations

import json
from pathlib import Path

SAMPLES: list[dict] = []


def sample(name: str, label: str, family: str, headers: dict[str, str], body: str,
           attachments: list[dict] | None = None, html: bool = False) -> None:
    SAMPLES.append({
        "name": name, "label": label, "family": family,
        "headers": headers, "body": body,
        "attachments": attachments or [], "html": html,
    })


AUTH_PASS = "mx.northwind-logistics.com; spf=pass smtp.mailfrom=northwind-logistics.com; dkim=pass header.d=northwind-logistics.com; dmarc=pass"
AUTH_FAIL = "mx.northwind-logistics.com; spf=fail smtp.mailfrom=mail-secure-pay.info; dkim=none; dmarc=fail"
AUTH_SOFT = "mx.northwind-logistics.com; spf=softfail; dkim=none; dmarc=fail"

RECV_NORMAL = "from mail.northwind-logistics.com (mail.northwind-logistics.com [198.51.100.24]) by mx.northwind-logistics.com with ESMTPS id 4aB2; Mon, 08 Sep 2026 09:14:02 +0000"
RECV_EXTERNAL = "from unknown (vps-4471.hostwind.ru [203.0.113.88]) by mx.northwind-logistics.com with ESMTP id 9zQ1; Mon, 08 Sep 2026 03:22:41 +0000"

# ---------------------------------------------------------------------------
# MALICIOUS - CEO fraud / display-name spoofing
# ---------------------------------------------------------------------------

sample(
    "bec_01_ceo_wire_urgent", "MALICIOUS", "ceo_fraud",
    {
        "From": '"Ravi Menon (CEO)" <r.menon@northwind-l0gistics.com>',
        "To": "priya.sharma@northwind-logistics.com",
        "Reply-To": "ravi.menon.exec@gmail.com",
        "Return-Path": "<bounce@mail-secure-pay.info>",
        "Subject": "Urgent - confidential wire transfer needed today",
        "Date": "Mon, 08 Sep 2026 03:22:41 +0000",
        "Message-ID": "<9f2c1a@mail-secure-pay.info>",
        "Authentication-Results": AUTH_FAIL,
        "Received": RECV_EXTERNAL,
    },
    """Priya,

I need you to process an urgent wire transfer of USD 48,500.00 today before
close of business. This relates to a confidential acquisition and must be kept
strictly between us until the announcement.

Please do not discuss this with anyone else in finance. I am currently in
back-to-back meetings and cannot talk on the phone.

Beneficiary: Halden Trade Partners Ltd
IBAN: GB29NWBK60161331926819
Account number: 60161331

Confirm once the payment has been released.

Ravi Menon
Chief Executive Officer
Northwind Logistics
""",
)

sample(
    "bec_02_vendor_bank_change", "MALICIOUS", "vendor_invoice",
    {
        "From": '"Accounts - Delaney Freight" <accounts@delaney-freight.co>',
        "To": "accounts.payable@northwind-logistics.com",
        "Reply-To": "delaney.accounts.dept@outlook.com",
        "Subject": "Re: Invoice INV-20881 - updated bank details",
        "Date": "Tue, 09 Sep 2026 11:05:12 +0000",
        "Message-ID": "<c71a3@delaney-freight.co>",
        "Authentication-Results": AUTH_SOFT,
        "Received": RECV_EXTERNAL,
    },
    """Good morning,

Further to our conversation, please note that our banking details have changed
following a restructure of our treasury operations.

Kindly update your records before settling the outstanding balance of
EUR 27,340.00 on invoice INV-20881.

New bank details:
  Beneficiary: Delaney Freight Solutions
  IBAN: LT121000011101001000
  SWIFT: LTXXLT2X

Please confirm the payment has been remitted to the new account today, as the
deadline for this quarter's reconciliation is approaching.

Regards,
Marta Kalina
Accounts Receivable
""",
)

sample(
    "bec_03_gift_card", "MALICIOUS", "gift_card",
    {
        "From": '"Sandra Whitlock - CFO" <sandra.whitlock.cfo@gmail.com>',
        "To": "j.okafor@northwind-logistics.com",
        "Subject": "Quick favour - are you at your desk?",
        "Date": "Wed, 10 Sep 2026 06:41:00 +0000",
        "Message-ID": "<aa41f@mail.gmail.com>",
        "Authentication-Results": "mx.northwind-logistics.com; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass",
        "Received": RECV_EXTERNAL,
    },
    """Hi Joseph,

I need you to handle something for me discreetly. We are recognising the
warehouse team this week and I want to surprise them.

Can you purchase 10 Amazon gift cards at 100 each and send me the redeem codes
from the back of the cards? I will approve the expense claim personally when I
am back.

I am travelling and cannot talk right now, so please just reply here. Keep this
between us until the announcement.

Thanks,
Sandra Whitlock
Chief Financial Officer
""",
)

sample(
    "bec_04_payroll_diversion", "MALICIOUS", "payroll_diversion",
    {
        "From": '"Daniel Osei" <d.osei@northwind-logistlcs.com>',
        "To": "hr.payroll@northwind-logistics.com",
        "Subject": "Change of account for salary payment",
        "Date": "Thu, 11 Sep 2026 22:18:33 +0000",
        "Message-ID": "<7bd90@northwind-logistlcs.com>",
        "Authentication-Results": AUTH_FAIL,
        "Received": RECV_EXTERNAL,
    },
    """Hello Payroll,

I have changed banks and would like my salary paid into a different account
starting with this month's run.

New account details:
  Sort code: 20-45-11
  Account number: 81440273

Please update your records before the payroll cut-off. Let me know once done.

Kind regards,
Daniel Osei
""",
)

sample(
    "bec_05_credential_phish", "MALICIOUS", "credential_harvest",
    {
        "From": '"Northwind IT Helpdesk" <it-support@northwind-secure-portal.com>',
        "To": "all.staff@northwind-logistics.com",
        "Reply-To": "helpdesk.verify@yandex.com",
        "Subject": "Action required: your mailbox password will expire in 2 hours",
        "Date": "Fri, 12 Sep 2026 04:55:10 +0000",
        "Message-ID": "<ff120@northwind-secure-portal.com>",
        "Authentication-Results": AUTH_FAIL,
        "Received": RECV_EXTERNAL,
    },
    """Dear User,

Our records show that your password will expire in 2 hours. Your session
expired and your mailbox is full.

Please click here to verify your account and re-enter your credentials
immediately to avoid interruption of service.

This is a time sensitive notice. Failure to act now will result in loss of
access.

IT Helpdesk
Northwind Logistics
""",
)

sample(
    "bec_06_lawyer_pressure", "MALICIOUS", "ceo_fraud",
    {
        "From": '"Ravi Menon" <ravi.menon@northwind-logistics.com.secure-mx.net>',
        "To": "priya.sharma@northwind-logistics.com",
        "Reply-To": "r.menon.northwind@protonmail.com",
        "Subject": "Fw: Completion funds - handle personally",
        "Date": "Fri, 12 Sep 2026 23:47:19 +0000",
        "Message-ID": "<b0c4e@secure-mx.net>",
        "Authentication-Results": AUTH_SOFT,
        "Received": RECV_EXTERNAL,
    },
    """Priya,

As discussed earlier, our external counsel needs the completion funds remitted
today. The amount is GBP 62,000 and it is time-sensitive.

I am counting on you to handle this personally and not involve anyone else
until the deal is public. Do not copy the wider finance team.

Beneficiary details will follow from the solicitor. Please confirm you can
process the transfer as soon as possible.

Ravi
""",
)

sample(
    "bec_07_supplier_followup", "MALICIOUS", "vendor_invoice",
    {
        "From": '"Delaney Freight Accounts" <accounts@delaney-freíght.co>',
        "To": "accounts.payable@northwind-logistics.com",
        "Subject": "Re: outstanding remittance",
        "Date": "Sat, 13 Sep 2026 02:12:00 +0000",
        "Message-ID": "<dd71b@delaney-freight.co>",
        "Authentication-Results": AUTH_FAIL,
        "Received": RECV_EXTERNAL,
    },
    """Hello,

Per my last email, the invoice remains unpaid. Please process the payment to
the new beneficiary account urgently - our auditors are closing the period
today.

Amount due: USD 19,200.00

Regards,
Marta
""",
)

# ---------------------------------------------------------------------------
# SUSPICIOUS - genuine-looking but with weak signals
# ---------------------------------------------------------------------------

sample(
    "susp_01_external_invoice", "SUSPICIOUS", "external_finance",
    {
        "From": '"Harborline Supplies" <billing@harborline-supplies.com>',
        "To": "accounts.payable@northwind-logistics.com",
        "Subject": "Invoice HS-4471 attached",
        "Date": "Mon, 08 Sep 2026 14:30:00 +0000",
        "Message-ID": "<4471@harborline-supplies.com>",
        "Authentication-Results": "mx.northwind-logistics.com; spf=pass smtp.mailfrom=harborline-supplies.com; dkim=pass header.d=harborline-supplies.com; dmarc=pass",
        "Received": RECV_NORMAL,
    },
    """Hello,

Please find invoice HS-4471 for GBP 1,840.00 covering September pallet supply.

Payment is due within 30 days to our usual account. Let us know if you need a
copy of the purchase order.

Thanks,
Harborline Supplies Billing
""",
)

sample(
    "susp_02_urgent_legit", "SUSPICIOUS", "internal_urgent",
    {
        "From": '"Priya Sharma" <priya.sharma@northwind-logistics.com>',
        "To": "warehouse.leads@northwind-logistics.com",
        "Subject": "URGENT: stocktake figures needed before close of business",
        "Date": "Mon, 08 Sep 2026 16:02:00 +0000",
        "Message-ID": "<stk881@northwind-logistics.com>",
        "Authentication-Results": AUTH_PASS,
        "Received": RECV_NORMAL,
    },
    """Team,

I need the stocktake figures urgently - auditors are on site tomorrow morning
and I must submit before close of business today.

Please send your counts as soon as possible.

Priya
""",
)

# ---------------------------------------------------------------------------
# BENIGN - normal internal and external business traffic
# ---------------------------------------------------------------------------

sample(
    "ben_01_internal_meeting", "BENIGN", "internal_routine",
    {
        "From": '"Priya Sharma" <priya.sharma@northwind-logistics.com>',
        "To": "j.okafor@northwind-logistics.com",
        "Subject": "Notes from the depot review",
        "Date": "Mon, 08 Sep 2026 10:15:00 +0000",
        "Message-ID": "<dep01@northwind-logistics.com>",
        "Authentication-Results": AUTH_PASS,
        "Received": RECV_NORMAL,
    },
    """Joseph,

Attaching my notes from this morning's depot review. The main action is the
forklift servicing schedule - can you confirm the dates with the contractor?

No rush, end of week is fine.

Priya
""",
)

sample(
    "ben_02_it_maintenance", "BENIGN", "internal_routine",
    {
        "From": '"Northwind IT" <it@northwind-logistics.com>',
        "To": "all.staff@northwind-logistics.com",
        "Subject": "Planned maintenance this Saturday",
        "Date": "Tue, 09 Sep 2026 09:00:00 +0000",
        "Message-ID": "<maint22@northwind-logistics.com>",
        "Authentication-Results": AUTH_PASS,
        "Received": RECV_NORMAL,
    },
    """Hello all,

We will be carrying out planned maintenance on the file server this Saturday
between 08:00 and 12:00. Shared drives may be briefly unavailable.

No action is needed from you. If you have questions, raise a ticket through the
service desk as usual.

Northwind IT
""",
)

sample(
    "ben_03_vendor_normal", "BENIGN", "external_routine",
    {
        "From": '"Delaney Freight Accounts" <accounts@delaney-freight.co>',
        "To": "accounts.payable@northwind-logistics.com",
        "Subject": "Statement for August",
        "Date": "Tue, 09 Sep 2026 13:20:00 +0000",
        "Message-ID": "<stmt08@delaney-freight.co>",
        "Authentication-Results": "mx.northwind-logistics.com; spf=pass smtp.mailfrom=delaney-freight.co; dkim=pass header.d=delaney-freight.co; dmarc=pass",
        "Received": RECV_NORMAL,
    },
    """Good afternoon,

Please find our statement for August. All invoices are settled and there is no
outstanding balance.

Our bank details are unchanged.

Best regards,
Marta Kalina
Delaney Freight Solutions
""",
)

sample(
    "ben_04_hr_policy", "BENIGN", "internal_routine",
    {
        "From": '"HR Team" <hr@northwind-logistics.com>',
        "To": "all.staff@northwind-logistics.com",
        "Subject": "Updated remote working policy",
        "Date": "Wed, 10 Sep 2026 11:45:00 +0000",
        "Message-ID": "<hr991@northwind-logistics.com>",
        "Authentication-Results": AUTH_PASS,
        "Received": RECV_NORMAL,
    },
    """Hi everyone,

The updated remote working policy is now on the intranet. The main change is
that core hours are now 10:00 to 15:00.

Please read it when you get a chance and direct any questions to your line
manager.

HR Team
""",
)

sample(
    "ben_05_customer_query", "BENIGN", "external_routine",
    {
        "From": '"Tomas Berg" <t.berg@bergindustrial.se>',
        "To": "sales@northwind-logistics.com",
        "Subject": "Question about pallet dimensions",
        "Date": "Wed, 10 Sep 2026 15:10:00 +0000",
        "Message-ID": "<q4410@bergindustrial.se>",
        "Authentication-Results": "mx.northwind-logistics.com; spf=pass smtp.mailfrom=bergindustrial.se; dkim=pass header.d=bergindustrial.se; dmarc=pass",
        "Received": RECV_NORMAL,
    },
    """Hello,

Could you confirm the maximum pallet dimensions you can accept at the Rotterdam
depot? We are planning a shipment for next month.

Thanks in advance,
Tomas Berg
Berg Industrial AB
""",
)

sample(
    "ben_06_newsletter", "BENIGN", "external_routine",
    {
        "From": '"Logistics Weekly" <news@logisticsweekly.example>',
        "To": "priya.sharma@northwind-logistics.com",
        "Subject": "This week in freight: capacity tightens",
        "Date": "Thu, 11 Sep 2026 07:30:00 +0000",
        "Message-ID": "<nl2209@logisticsweekly.example>",
        "Authentication-Results": "mx.northwind-logistics.com; spf=pass smtp.mailfrom=logisticsweekly.example; dkim=pass header.d=logisticsweekly.example; dmarc=pass",
        "Received": RECV_NORMAL,
    },
    """Logistics Weekly

Capacity on northern European routes tightened again this week as seasonal
demand picked up. Rates rose modestly across most lanes.

Read the full analysis on our website. To stop receiving this newsletter, use
the unsubscribe link below.
""",
)

sample(
    "ben_07_internal_finance", "BENIGN", "internal_finance",
    {
        "From": '"Sandra Whitlock" <sandra.whitlock@northwind-logistics.com>',
        "To": "accounts.payable@northwind-logistics.com",
        "Subject": "Q3 budget review scheduled",
        "Date": "Thu, 11 Sep 2026 10:05:00 +0000",
        "Message-ID": "<q3rev@northwind-logistics.com>",
        "Authentication-Results": AUTH_PASS,
        "Received": RECV_NORMAL,
    },
    """Hello,

The Q3 budget review is scheduled for the 24th. Please have your departmental
figures ready a few days beforehand.

Nothing is needed from you before then.

Sandra Whitlock
Chief Financial Officer
Northwind Logistics
""",
)

sample(
    "ben_08_delivery_notice", "BENIGN", "external_routine",
    {
        "From": '"Depot Scheduling" <scheduling@northwind-logistics.com>',
        "To": "warehouse.leads@northwind-logistics.com",
        "Subject": "Friday delivery window confirmed",
        "Date": "Fri, 12 Sep 2026 08:20:00 +0000",
        "Message-ID": "<dw551@northwind-logistics.com>",
        "Authentication-Results": AUTH_PASS,
        "Received": RECV_NORMAL,
    },
    """Team,

The Friday delivery window is confirmed for 13:00-15:00. Standard unloading
procedure applies.

Depot Scheduling
""",
)



# ---------------------------------------------------------------------------
# CASE 4 - fabricated / hijacked conversation (three-message thread)
#
# The first two messages are the genuine exchange. The third is the attacker
# grafting onto it: same subject, a new Reply-To, and the conversation turns
# financial for the first time.
# ---------------------------------------------------------------------------

sample(
    "thread_01_genuine_opening", "BENIGN", "thread_genuine",
    {
        "From": '"Marta Kalina" <m.kalina@delaney-freight.co>',
        "To": "j.okafor@northwind-logistics.com",
        "Cc": "accounts.payable@northwind-logistics.com",
        "Subject": "Pallet contract renewal - Q4 schedule",
        "Date": "Mon, 01 Sep 2026 09:12:00 +0000",
        "Message-ID": "<thread-aaa-001@delaney-freight.co>",
        "Authentication-Results": "mx.northwind-logistics.com; spf=pass smtp.mailfrom=delaney-freight.co; dkim=pass header.d=delaney-freight.co; dmarc=pass",
        "Received": RECV_NORMAL,
    },
    """Good morning,

Ahead of the Q4 schedule I wanted to confirm the pallet volumes we discussed at
the depot review. Our proposed figures are on the contract portal as usual.

Could you confirm the delivery windows suit your side?

Best regards,
Marta Kalina
Delaney Freight Solutions
""",
)

sample(
    "thread_02_genuine_reply", "BENIGN", "thread_genuine",
    {
        "From": '"Joseph Okafor" <j.okafor@northwind-logistics.com>',
        "To": "m.kalina@delaney-freight.co",
        "Cc": "accounts.payable@northwind-logistics.com",
        "Subject": "Re: Pallet contract renewal - Q4 schedule",
        "Date": "Mon, 01 Sep 2026 14:40:00 +0000",
        "Message-ID": "<thread-aaa-002@northwind-logistics.com>",
        "In-Reply-To": "<thread-aaa-001@delaney-freight.co>",
        "References": "<thread-aaa-001@delaney-freight.co>",
        "Authentication-Results": AUTH_PASS,
        "Received": RECV_NORMAL,
    },
    """Hi Marta,

Thanks - the volumes look right to me. The Tuesday and Thursday windows work
best for our depot team.

I have copied accounts payable so they are aware of the renewal.

Joseph Okafor
Northwind Logistics
""",
)

sample(
    "thread_03_hijack", "MALICIOUS", "thread_hijack",
    {
        "From": '"Marta Kalina" <m.kalina@delaney-freight.co>',
        "To": "accounts.payable@northwind-logistics.com",
        "Reply-To": "m.kalina.delaney@mail.com",
        "Subject": "Re: Pallet contract renewal - Q4 schedule",
        "Date": "Tue, 02 Sep 2026 23:58:00 +0000",
        "Message-ID": "<thread-aaa-003@delaney-freight.co>",
        "In-Reply-To": "<thread-aaa-002@northwind-logistics.com>",
        "References": "<thread-aaa-001@delaney-freight.co> <thread-aaa-002@northwind-logistics.com>",
        "Authentication-Results": AUTH_SOFT,
        "Received": RECV_EXTERNAL,
    },
    """Hello,

Further to our conversation on the renewal, please note our banking details
have changed ahead of the Q4 invoices.

Kindly update your records and remit the outstanding balance of GBP 18,450.00
to the new account today - our auditors close the period this evening.

  Beneficiary: Delaney Freight Solutions
  IBAN: LT601010012345678901

Please keep this between us until the contract is countersigned.

Marta
""",
)

# ---------------------------------------------------------------------------
# CASE 3 (extended) - look-alike domain carrying a deceptive link and a
# double-extension executable attachment.
# ---------------------------------------------------------------------------

sample(
    "bec_08_link_and_attachment", "MALICIOUS", "credential_harvest",
    {
        "From": '"Northwind Payroll" <payroll@northwind-logistics.support>',
        "To": "all.staff@northwind-logistics.com",
        "Reply-To": "payroll.verify@yandex.com",
        "Subject": "Payslip correction - action required today",
        "Date": "Wed, 03 Sep 2026 04:11:00 +0000",
        "Message-ID": "<pay991@northwind-logistics.support>",
        "Authentication-Results": AUTH_FAIL,
        "Received": RECV_EXTERNAL,
    },
    """<html><body>
<p>Dear Colleague,</p>
<p>A correction has been applied to your latest payslip. You must verify your
account immediately to receive the adjusted payment.</p>
<p><a href="http://203.0.113.45/payroll/secure/login.php">https://payroll.northwind-logistics.com/verify</a></p>
<p>This is time sensitive. Failure to act now will delay your payment.</p>
<p>Northwind Payroll</p>
</body></html>
""",
    attachments=[{
        "filename": "Payslip_September.pdf.exe",
        "mime": "application/pdf",
        # Fake PE header. Inert test bytes - not a real executable.
        "content": b"MZ\x90\x00\x03\x00\x00\x00 inert test payload, not an executable",
    }],
    html=True,
)

# ---------------------------------------------------------------------------
# CASE 5 (reinforced) - legitimate urgent email WITH a financial reference.
#
# The critical control case: urgency + a real sum + a real deadline, but a
# verified internal sender referring to an account already on file. It must
# NOT be flagged, demonstrating that urgency alone is not BEC.
# ---------------------------------------------------------------------------

sample(
    "susp_03_legit_urgent_payment", "BENIGN", "internal_urgent",
    {
        "From": '"Sandra Whitlock" <sandra.whitlock@northwind-logistics.com>',
        "To": "accounts.payable@northwind-logistics.com",
        "Subject": "URGENT: Harborline invoice must be paid before close of business",
        "Date": "Thu, 04 Sep 2026 10:22:00 +0000",
        "Message-ID": "<urg551@northwind-logistics.com>",
        "Authentication-Results": AUTH_PASS,
        "Received": RECV_NORMAL,
    },
    """Team,

The Harborline invoice HS-4471 for GBP 1,840.00 needs to be paid before close
of business today or we lose the early settlement discount.

Details are unchanged and already on file - this is the same account we have
always used. Please process it through the normal approval workflow.

Sandra Whitlock
Chief Financial Officer
Northwind Logistics
""",
)



# ---------------------------------------------------------------------------
# CASE 6 - account takeover, demonstrating stylometry
#
# Four messages from the same internal address. The first three establish this
# sender's writing baseline (long measured sentences, "Good morning," opening,
# full name + title sign-off). The fourth comes from the same mailbox but is
# written by someone else: short clipped sentences, exclamation marks, a
# different greeting and a truncated sign-off.
#
# Identity checks alone cannot catch this - the address is real, internal and
# fully authenticated. Only comparison against the sender's OWN prior writing
# raises it.
# ---------------------------------------------------------------------------

_ATO_HEADERS = {
    "From": '"Elena Fischer" <e.fischer@northwind-logistics.com>',
    "To": "accounts.payable@northwind-logistics.com",
    "Authentication-Results": AUTH_PASS,
    "Received": RECV_NORMAL,
}

sample(
    "ato_01_baseline", "BENIGN", "ato_baseline",
    {**_ATO_HEADERS,
     "Subject": "Quarterly supplier reconciliation schedule",
     "Date": "Mon, 18 Aug 2026 09:30:00 +0000",
     "Message-ID": "<ato-base-001@northwind-logistics.com>"},
    """Good morning,

I have completed the reconciliation schedule for the coming quarter, and I
would be grateful if you could review the supplier groupings before we
circulate them to the wider finance function.

The principal change this quarter concerns the consolidation of the smaller
haulage accounts, which should reduce the administrative overhead considerably
without affecting our payment terms.

Please let me know if anything requires adjustment.

Kind regards,
Elena Fischer
Financial Controller
Northwind Logistics
""",
)

sample(
    "ato_02_baseline", "BENIGN", "ato_baseline",
    {**_ATO_HEADERS,
     "Subject": "Notes on the August ledger review",
     "Date": "Wed, 20 Aug 2026 11:15:00 +0000",
     "Message-ID": "<ato-base-002@northwind-logistics.com>"},
    """Good morning,

Following the ledger review yesterday, I have summarised the three outstanding
queries that remain open, together with the supporting documentation that will
be required in order to close them.

None of these are urgent, and I would suggest we address them alongside the
month-end process rather than interrupting the current workload.

Kind regards,
Elena Fischer
Financial Controller
Northwind Logistics
""",
)

sample(
    "ato_03_baseline", "BENIGN", "ato_baseline",
    {**_ATO_HEADERS,
     "Subject": "Depot expenditure summary for July",
     "Date": "Fri, 22 Aug 2026 14:05:00 +0000",
     "Message-ID": "<ato-base-003@northwind-logistics.com>"},
    """Good morning,

Please find below the expenditure summary for the depot operations during July,
which I have reconciled against the approved budget allocation for the period.

Expenditure remains within the agreed tolerance, and I do not anticipate any
variance that would require escalation to the finance committee at this stage.

Kind regards,
Elena Fischer
Financial Controller
Northwind Logistics
""",
)

sample(
    "ato_04_takeover", "MALICIOUS", "account_takeover",
    {**_ATO_HEADERS,
     "Subject": "payment needed",
     "Date": "Sat, 23 Aug 2026 02:47:00 +0000",
     "Message-ID": "<ato-base-004@northwind-logistics.com>"},
    """Hey!

Need you to do a wire transfer now! Amount is USD 34,500. It is urgent!

New bank details below. Update your records please!

IBAN: LT991010098765432101

Do it today! Do not discuss with anyone! I am busy!

Thanks!
E
""",
)


def _build_message(item: dict) -> bytes:
    """Serialise one sample to RFC 5322 bytes, with MIME parts where needed."""
    import email.message

    msg = email.message.EmailMessage()
    for key, value in item["headers"].items():
        msg[key] = value

    body = item["body"]
    if item.get("html"):
        msg.set_content("This message requires an HTML capable client.")
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)

    for attachment in item.get("attachments", []):
        maintype, _, subtype = attachment["mime"].partition("/")
        msg.add_attachment(
            attachment["content"],
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=attachment["filename"],
        )

    return msg.as_bytes()


def write_corpus(target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)

    labels: dict[str, dict[str, str]] = {}
    for item in SAMPLES:
        raw = _build_message(item)

        filename = f"{item['name']}.eml"
        # Write bytes, not text: on Windows write_text() would translate the
        # "\r\n" line endings again into "\r\r\n" and corrupt the header block.
        (target / filename).write_bytes(raw)
        labels[filename] = {"label": item["label"], "family": item["family"]}

    (target / "labels.json").write_text(
        json.dumps(labels, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    counts: dict[str, int] = {}
    for meta in labels.values():
        counts[meta["label"]] = counts.get(meta["label"], 0) + 1
    print(f"wrote {len(labels)} messages to {target}")
    for label, count in sorted(counts.items()):
        print(f"  {label:<12} {count}")


if __name__ == "__main__":
    write_corpus(Path(__file__).parent / "samples")
