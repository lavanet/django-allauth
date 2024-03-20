from django.forms import Form, fields
from django.core.exceptions import ValidationError

 
class WalletLoginForm(Form):
    login_token = fields.CharField(required=False)
    account = fields.CharField(required=True)
    public_key = fields.CharField(required=False)
    process = fields.CharField(required=True)
    invite_code = fields.CharField(required=False, max_length=5)
    base_login_token = fields.CharField(required=False)
    
    def clean(self):
        cleaned_data = super().clean()
        login_token = cleaned_data.get("login_token")
        process = cleaned_data.get("process")

        if process == "verify" and not login_token:
            raise ValidationError("Login token is required when process is 'verify'.")

        return cleaned_data
