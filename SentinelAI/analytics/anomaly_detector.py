import math
from typing import Dict, Any

class StatisticalAnomalyDetector:
    @staticmethod
    def calculate_z_score(current_amount: float, median: float, std: float) -> float:
        if std <= 0:
            return 0.0
        return round((current_amount - median) / std, 2)

    @staticmethod
    def check_iqr_outlier(current_amount: float, median: float, iqr_multiplier: float = 1.5) -> bool:
        # Simplified IQR check against median baseline
        threshold = median * (1.0 + iqr_multiplier * 2.0)
        return current_amount > max(threshold, 500.0)

    @staticmethod
    def estimate_geo_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        # Haversine formula approximation
        R = 6371.0
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return round(R * c, 1)

    @classmethod
    def check_impossible_travel(cls, prev_city: str, current_city: str) -> float:
        """
        Mock distance calculation between known city coordinates for geo-velocity.
        Returns approx distance in km.
        """
        CITY_COORDS = {
            "Warsaw": (52.2297, 21.0122),
            "Krakow": (50.0647, 19.9450),
            "Berlin": (52.5200, 13.4050),
            "Munich": (48.1351, 11.5820),
            "London": (51.5074, -0.1278),
            "Tokyo": (35.6762, 139.6503),
            "Pyongyang": (39.0392, 125.7625)
        }
        if prev_city == current_city or prev_city not in CITY_COORDS or current_city not in CITY_COORDS:
            return 0.0
        
        c1 = CITY_COORDS[prev_city]
        c2 = CITY_COORDS[current_city]
        return cls.estimate_geo_distance(c1[0], c1[1], c2[0], c2[1])
