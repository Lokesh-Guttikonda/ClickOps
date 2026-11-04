"""terradrift-ai: autonomous Terraform ClickOps drift reconciler.

Pipeline::

    detector          -> which resources drifted, and which attributes?
    cloudtrail_lookup -> who changed them, when, and from where?
    hcl_patcher       -> update the .tf code so it matches live infrastructure
    pr_creator        -> open a pull request with the patch and an audit table

When installed with ``pip install .`` this directory is importable as ``terradrift``;
inside a clone it is importable as ``src`` (that is what the tests and the demo use).
"""

__version__ = "0.1.0"
