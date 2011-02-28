# -*- coding: utf-8 -*-
"""Routes configuration

The more specific and detailed routes should be defined first so they
may take precedent over the more generic routes. For more information
refer to the routes manual at http://routes.groovie.org/docs/
"""
# from pylons import config
from routes import Mapper

def make_map(config):
    """Create, configure and return the routes Mapper"""
    map = Mapper(directory=config['pylons.paths']['controllers'],
                 always_scan=config['debug'])
    map.explicit = False
    map.minimization = True

    # The ErrorController route (handles 404/500 error pages); it should
    # likely stay at the top, ensuring it can always be resolved
    map.connect('/error/{action}/{id}', controller='error')

    # CUSTOM ROUTES HERE

    map.connect('/', controller='packages', action='index')
    map.connect('/search', controller='packages', action='quicksearch')
    map.connect('/quicksearch', controller='packages', action='quicksearch')
    map.connect('/archswitch/{arch}', controller='packages', action='archswitch')
    map.connect('/viewswitch/{view}', controller='packages', action='viewswitch')
    map.connect('/updateswitch/{amount}', controller='packages', action='updateswitch')
    map.connect('/updatetype/{update_type}', controller='packages', action='updatetype')
    map.connect('/sortswitch/{sortby}', controller='packages', action='sortswitch')
    map.connect('/getinstall', controller='packages', action='getinstall')

    map.connect('/group/{group}', controller='packages', action='group')
    map.connect('/category/{category}', controller='packages', action='category')
    map.connect('/license/{license}', controller='packages', action='license')
    map.connect('/useflag/{useflag}', controller='packages', action='useflag')
    map.connect('/show/{hash_id}', controller='packages', action='show')
    map.connect('/show/{hash_id}/{what}', controller='packages',
        action='show_what')
    map.connect('/groups', controller='packages', action='groups')
    map.connect('/categories', controller='packages', action='categories')

    map.connect('/api', controller='api', action='execute')
    map.connect('/logout', controller='login', action='logout')
    map.connect('/connect', controller='login', action='submit')
    map.connect('/{controller}/{action}/{id}')
    map.connect('/{controller}/{action}')
    map.connect('/{controller}', action='index')
    map.connect('*url', controller='template', action='view')

    return map
