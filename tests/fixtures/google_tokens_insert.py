# Fixture: Callitin google_tokens unencrypted storage
import supabase


def save_tokens(user_id, refresh_token, access_token):
    supabase.table("google_tokens").upsert({
        "user_id": user_id,
        "refresh_token": refresh_token,
        "access_token": access_token,
    }).execute()
