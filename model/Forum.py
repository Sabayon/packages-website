import os
import config
from entropy.const import *
etpConst['entropygid'] = config.DEFAULT_WEB_GID
from www.lib.phpbb import Authenticator as phpBB3AuthInterface

class Forum(phpBB3AuthInterface):

    def __init__(self):
        phpBB3AuthInterface.__init__(self)
        self.set_connection_data(config.phpbb_connection_data)
        self.connect()
        self.dbconn.set_character_set('utf8')

    def get_latest_posts(self, limit = 5):
        self.execute_query('select SQL_CACHE phpbb_users.username, phpbb_users.username_clean, phpbb_topics.topic_id, phpbb_topics.topic_title, phpbb_posts.post_text FROM phpbb_topics,phpbb_users,phpbb_posts WHERE phpbb_topics.topic_poster = phpbb_users.user_id AND phpbb_topics.topic_id = phpbb_posts.topic_id GROUP BY phpbb_topics.topic_id ORDER BY topic_id DESC LIMIT 0,%d' % (limit,))
        data = self.fetchall()
        for item in data:
            t = config.remove_html_tags(item['post_text'])
            t = config.remove_phpbb_tags(t)
            item['post_text'] = t
            t = config.remove_html_tags(item['topic_title'])
            t = config.remove_phpbb_tags(t)
            item['topic_title'] = t
        return data

    def count_users(self):
        self.execute_query('SELECT SQL_CACHE count(user_id) as mycount FROM phpbb_users')
        data = self.fetchone()
        if isinstance(data,dict):
            if data.has_key('mycount'):
                return data.get('mycount')
        return 0

    def search_email(self, email):
        self.execute_query('SELECT SQL_CACHE user_id,username_clean as username FROM phpbb_users WHERE user_email LIKE %s', ("%"+email+"%",))
        return self.fetchall()

    def search_user_id(self, user_id):
        self.execute_query('SELECT SQL_CACHE user_id,username_clean as username FROM phpbb_users WHERE user_id = %s', (user_id,))
        return self.fetchall()

    def search_username(self, username, strict = False):

        strict_string = 'LIKE'
        if len(username) < 3:
            strict = True
            strict_string = '='

        self.execute_query('SELECT SQL_CACHE user_id,username FROM phpbb_users WHERE phpbb_users.username_clean '+strict_string+' %s OR phpbb_users.username '+strict_string+' %s', ("%"+username+"%","%"+username+"%",))
        return self.fetchall()

    def __del__(self):
        if hasattr(self,'disconnect'):
            self.disconnect()
