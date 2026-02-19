"""
Permet d'exécuter le package scanners directement :
    python -m src.scanners --mock
    python -m src.scanners --mock --save

Redirige vers le scanner AWS par défaut.
En Phase 6-7, ajoutera --cloud azure|gcp.
"""

from src.scanners.aws_scanner import main

main()
