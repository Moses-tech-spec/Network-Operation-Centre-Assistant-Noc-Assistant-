from pprint import pprint

from app.ai.recommendations import MayaRecommendations

pprint(
    MayaRecommendations.recommend("Your router Name")
)
