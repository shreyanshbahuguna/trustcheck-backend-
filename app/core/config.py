import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    # Application Environment
    APP_ENV: str = "development"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database + Cache
    DATABASE_URL: str
    REDIS_URL: str

    # WHOIS (optional external API, but we keep fields for compatibility)
    WHOIS_API_KEY: str = ""
    WHOIS_API_URL: str = ""

    # News API (for scam/fraud detection)
    NEWS_API_KEY: str = ""
    NEWS_API_URL: str = ""

    # VirusTotal API (IMPORTANT)
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_API_URL: str = "https://www.virustotal.com/api/v3"

    # MCA Scraper
    MCA_SCRAPER_USER_AGENT: str = "TrustCheckBot/1.0"

    # Phishing API (optional future integration)
    PHISHTANK_API_KEY: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Create settings instance
settings = Settings()
