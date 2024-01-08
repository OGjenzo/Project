# App/forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser  # Import your CustomUser model
from .models import Reclamation
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'password1', 'password2']

class CustomAuthenticationForm(AuthenticationForm):
    # Add any additional fields or customization here if needed
    pass

class ReclamationForm(forms.ModelForm):
    class Meta:
        model = Reclamation
        fields = ['encrypted_message']

    def save(self, commit=True):
        reclamation = super().save(commit=False)
        user_public_key = serialization.load_pem_public_key(
            self.instance.user.encryption_key.encode(),
            backend=default_backend()
        )

        # Generate a random IV
        iv = os.urandom(16)
        reclamation.iv = iv

        # Encrypt the message
        cipher = Cipher(algorithms.AES(user_public_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(self.cleaned_data['encrypted_message'].encode()) + encryptor.finalize()
        reclamation.encrypted_message = encrypted_message

        if commit:
            reclamation.save()
        return reclamation