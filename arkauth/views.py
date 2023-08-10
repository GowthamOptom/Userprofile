from email.message import EmailMessage
from django.shortcuts import render,HttpResponse,redirect
from django.contrib import messages
from django.views.generic import View
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.models import User
# to activate the user accounts
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.urls import reverse, NoReverseMatch
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes,force_str,DjangoUnicodeDecodeError
#getting Token from utils.py
from .utils import TokenGenerator,generate_token
# emails
from django.core.mail import send_mail,EmailMultiAlternatives
from django.core.mail import BadHeaderError,send_mail
from django.core import mail
from django.conf import settings
from django.core.mail import EmailMessage
# Thereding
import threading

class EmailThread(threading.Thread):
    def __init__(self, email_message):
        self.email_message=email_message
        threading.Thread.__init__(self)
    def run(self):
        self.email_message.send()

def signup(request):
    if request.method == 'POST':
        email=request.POST.get('email')
        pass1=request.POST.get('pass1')
        pass2=request.POST.get('pass2')
        if pass1 != pass2:

            messages.error(request,"Password do not Match,Please Try Again!")
            return render(request,"auth/signup.html")
        try:
            if User.objects.get(username=email):
                messages.warning(request,"Email Already Exists")
                return render(request,"auth/signup.html")
        except Exception as identifier:            
            pass       
        user=User.objects.create_user(email,email,pass1)
        user.is_active=False
        user.save()
        current_site=get_current_site(request)
        email_subject="Activate Your Account"
        message=render_to_string('arkauth/activate.html',{
            'user':user,
            'domain':'127.0.0.1:8000',
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)
        })
     
        email_message = EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
        EmailThread(email_message).start()
        messages.info(request,"Activate Your Account by clicking link on your email")
    return render(request,"auth/signup.html")


class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activated Successfully")
            return redirect('/arkauth/login')
        return render(request, 'auth/activatefail.html')



def handlelogin(request):
      if request.method == 'POST':
        loginusername=request.POST['email']
        loginpassword=request.POST['pass1'] 
        user=authenticate(username=loginusername,password=loginpassword)
       
        if user is not None:
            login(request,user)
            messages.info(request,"Successfully Logged In")
            return redirect('/')

        else:
            messages.error(request,"Invalid Credentials")
            return redirect('/arkauth/login/')        
      return render(request,'auth/login.html') 
        
def handlelogout(request):
    logout(request)
    messages.success(request,"Logout Success")
    return redirect('/arkauth/login/')