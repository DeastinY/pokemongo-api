#!/usr/bin/python
import argparse
import logging
import time
import sys
from custom_exceptions import GeneralPogoException

from api import PokeAuthSession
from location import Location

from pokedex import pokedex
from inventory import items

def setupLogger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('Line %(lineno)d,%(filename)s - %(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


# Example functions
# Get profile
def getProfile(session):
        logging.info("getProfile")
        return session.getProfile()

# Do Inventory stuff
def getInventory(session):
    logging.info("getInventory")
    return session.getInventory()

# For IV calculation
def calcIV(pokemon):
    IV = ((pokemon.individual_attack + pokemon.individual_defense + pokemon.individual_stamina )/45.0)*100.0
    return IV

# Entry point
# Start off authentication and demo
if __name__ == '__main__':
    setupLogger()
    logging.debug('Logger set up')

    # Read in args
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--auth", help="Auth Service", required=True)
    parser.add_argument("-u", "--username", help="Username", required=True)
    parser.add_argument("-p", "--password", help="Password", required=True)
    parser.add_argument("-l", "--location", help="Location", required=True)
    parser.add_argument("-g", "--geo_key", help="GEO API Secret")
    args = parser.parse_args()

    # Check service
    if args.auth not in ['ptc', 'google']:
        logging.error('Invalid auth service {}'.format(args.auth))
        sys.exit(-1)

    # Create PokoAuthObject
    poko_session = PokeAuthSession(
        args.username,
        args.password,
        args.auth,
        geo_key=args.geo_key
    )

    # Authenticate with a given location
    # Location is not inherent in authentication
    # But is important to session
    session = poko_session.authenticate(args.location)

    # Time to show off what we can do
    if session:

        # General
        inventory = getInventory(session)
        logging.info("Renaming Pokemon")
	for p in inventory.party:
            if not p.nickname in ["ADD_NICKNAMES_HERE_TO_SPARE_THEM"]:
                name = pokedex[p.pokemon_id]
                logging.info("Renaming {}".format(name))
                nick = "{:.0f} {} {} {}".format(calcIV(p), p.individual_attack,p.individual_defense,p.individual_stamina)
                logging.info("To "+nick)
                ret = session.nicknamePokemon(p, nick)
                logging.info(ret)
            else:
                logging.info("Skipping already nicknamed {}".format(p.nickname))

    else:
        logging.critical('Session not created successfully')
