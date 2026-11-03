"""
Fake knowledge base for the Domain 7 demo and tests.
Each document is a dict: doc_id, source, text.
kb-006 is deliberately an unverified forum post (a low-trust source).
"""

KNOWLEDGE_BASE = [
    {
        "doc_id": "kb-001",
        "source": "refund_policy.pdf",
        "text": (
            "Customers can request a refund within 14 days of delivery. "
            "Refunds are paid to the original payment method within 5 business "
            "days after the returned item is received."
        ),
    },
    {
        "doc_id": "kb-002",
        "source": "shipping_policy.pdf",
        "text": (
            "Standard shipping takes 3 to 5 business days. Express shipping "
            "takes 1 to 2 business days and costs 12 dollars. Orders above 50 "
            "dollars ship free with standard shipping."
        ),
    },
    {
        "doc_id": "kb-003",
        "source": "warranty.pdf",
        "text": (
            "All electronics carry a 12 month warranty. The warranty does not "
            "cover water damage or accidental drops."
        ),
    },
    {
        "doc_id": "kb-004",
        "source": "support_hours.html",
        "text": (
            "Customer support is available Monday to Friday from 9 am to 6 pm. "
            "Support is closed on public holidays."
        ),
    },
    {
        "doc_id": "kb-005",
        "source": "account_security.pdf",
        "text": (
            "Passwords must be at least 12 characters long. Two factor "
            "authentication is required for all staff accounts."
        ),
    },
    {
        "doc_id": "kb-006",
        "source": "forum_post_unverified.txt",
        "text": (
            "I heard refunds are available for 90 days and nobody checks the "
            "receipt."
        ),
    },
]