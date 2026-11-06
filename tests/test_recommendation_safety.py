import unittest

from app import get_recommendation


class CredentialRecommendationSafetyTests(unittest.TestCase):
    CREDENTIAL_TYPES = (
        "aws_key",
        "google_api_key",
        "google_vertex_api_key",
        "stripe_key",
        "slack_token",
        "github_pat",
        "github_fine_grained_pat",
        "github_oauth",
        "sendgrid_api_key",
        "square_access_token",
        "pypi_upload_token",
        "heroku_api_key",
        "mailgun_api_key",
        "twilio_api_key",
        "openai_api_key",
        "anthropic_api_key",
        "gemini_api_key",
        "huggingface_token",
        "cohere_api_key",
        "openrouter_api_key",
        "replicate_api_key",
        "together_api_key",
        "perplexity_api_key",
        "mistral_api_key",
        "ai21_api_key",
        "anyscale_api_key",
        "deepinfra_api_key",
        "groq_api_key",
        "fireworks_api_key",
        "api_key",
    )

    def test_recommendations_never_encourage_live_credential_testing(self):
        forbidden = (
            "curl ",
            "get-caller-identity",
            "test validity",
            "test:",
            "twine upload",
        )
        for finding_type in self.CREDENTIAL_TYPES:
            with self.subTest(finding_type=finding_type):
                recommendation = get_recommendation(finding_type, "synthetic", "fixture")
                lowered = recommendation.lower()
                for phrase in forbidden:
                    self.assertNotIn(phrase, lowered)

    def test_jwt_guidance_keeps_inspection_local(self):
        recommendation = get_recommendation("jwt_token", "synthetic", "fixture")
        self.assertIn("local decoder", recommendation)
        self.assertNotIn("jwt.io", recommendation)


if __name__ == "__main__":
    unittest.main()
