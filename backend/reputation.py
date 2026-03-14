from database import reporter_collection, reporter_helper
import time

SCORE_PER_SUBMISSION = 1.0
SCORE_PER_VERIFICATION = 2.0  # Submissions verified as valid earn bonus points
SCORE_HIGH_SEVERITY_BONUS = 0.5
MAX_REPUTATION = 100.0


async def get_or_create_reporter(reporter_id: str) -> dict:
    reporter = await reporter_collection.find_one({"reporter_id": reporter_id})
    if not reporter:
        new_reporter = {
            "reporter_id":      reporter_id,
            "submissions":      0,
            "verified_count":   0,
            "reputation_score": 0.0,
            "last_submission":  None,
        }
        await reporter_collection.insert_one(new_reporter)
        return new_reporter
    return reporter


async def update_reputation_on_submit(reporter_id: str, severity: str):
    """Increment score when a new indicator is submitted."""
    await get_or_create_reporter(reporter_id)

    bonus = SCORE_HIGH_SEVERITY_BONUS if severity in ("high", "critical") else 0.0
    increment = SCORE_PER_SUBMISSION + bonus

    await reporter_collection.update_one(
        {"reporter_id": reporter_id},
        {
            "$inc": {
                "submissions":      1,
                "reputation_score": increment
            },
            "$set": {
                "last_submission": str(int(time.time()))
            }
        }
    )


async def update_reputation_on_verify(reporter_id: str):
    """Bonus score when their submission is verified as valid."""
    await reporter_collection.update_one(
        {"reporter_id": reporter_id},
        {
            "$inc": {
                "verified_count":   1,
                "reputation_score": SCORE_PER_VERIFICATION
            }
        }
    )


async def get_leaderboard(limit: int = 10) -> list:
    """Top reporters by reputation score."""
    leaderboard = []
    async for r in reporter_collection.find().sort("reputation_score", -1).limit(limit):
        leaderboard.append(reporter_helper(r))
    return leaderboard