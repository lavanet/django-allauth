from django.forms import Form, fields

class WalletLoginForm(Form):
    login_token = fields.CharField(required=False)
    account = fields.CharField(required=True)
    public_key = fields.CharField(required=False)
    process = fields.CharField(required=True)
    invite_code = fields.CharField(required=False, max_length=5)
    base_login_token = fields.CharField(required=False)

    def clean(self):
        return super().clean()
