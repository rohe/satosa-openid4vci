from idpyoidc.server import user_info


class UserInfo(user_info.UserInfo):

    def load(self, info):
        self.db.update(info)
