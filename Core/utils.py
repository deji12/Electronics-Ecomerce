from django.shortcuts import redirect
from django.contrib.auth.models import User
import random
import string
    
def authenticate_user_with_email(email, password)-> User | None:

    """
    Authenticates a user with the given email and password.
    """
    

    try:
        # get the user object
        user = User.objects.get(email=email)

        # check if the entered password is correct
        if user.check_password(password):

            # return the user object if email and password are correct
            return user
        # return none if the password is incorrect
        return None
    except User.DoesNotExist:

        # return none if the email does not exist
        return None
    
def generate_random_code(length=6):

    """
    Generates a random code of the given length.
    """

    # define the characters that can be used in the code
    characters = string.ascii_uppercase + string.digits + string.ascii_lowercase

    # generate a random code with the given length and return it
    discount_code = ''.join(random.choice(characters) for _ in range(length))

    return discount_code