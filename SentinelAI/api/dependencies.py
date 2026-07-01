from fastapi import Header, HTTPException, status
from typing import Optional

async def verify_compliance_officer(x_api_key: Optional[str] = Header(None)):
    """
    Simulated API verification for compliance officers.
    Allows local development access without strict header if omitted or set to 'sentinel_dev'.
    """
    if x_api_key and x_api_key != "sentinel_dev":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Compliance Officer API Key"
        )
    return {"role": "senior_compliance_officer", "user": "officer_1"}
