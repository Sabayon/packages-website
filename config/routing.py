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
    map.connect('/ugc', controller='packages', action='ugc')
    map.connect('/stats', controller='packages', action='stats')
    map.connect('/categories', controller='packages', action='categories')
    map.connect('/releases', controller='packages', action='releases')
    map.connect('/advisories', controller='packages', action='advisories')
    map.connect('/repository/search/{repoid}/{product}/{arch}/{branch}/{pkgstring}', controller='packages', action='search_pkg')
    map.connect('/repository/search/{repoid}/{product}/{arch}/{branch}/{pkgcat}/{pkgnamever}', controller='packages', action='search_pkg_atom')
    map.connect('/repository/match/{repoid}/{product}/{arch}/{branch}/{pkgstring}', controller='packages', action='match_pkg')
    map.connect('/repository/match/{repoid}/{product}/{arch}/{branch}/{pkgcat}/{pkgnamever}', controller='packages', action='match_pkg_atom')
    map.connect('/ugc/search/{search_type}/{search_string}', controller='packages', action='search_ugc_package')
    map.connect('/ugc/search/{search_type}/{search_string}/{search_string2}', controller='packages', action='search_ugc_package')
    map.connect('/users/profile/{user}', controller='users', action='users_profile')
    map.connect('/community/my/{item}', controller='community', action='my_dispatcher')
    map.connect('/{controller}/{action}/{id}')
    map.connect('/{controller}/{action}')
    map.connect('/{controller}', action='index')
    map.connect('/{category}/{name}', controller='packages', action='catname')
    map.connect('*url', controller='template', action='view')

    return map
