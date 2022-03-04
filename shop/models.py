from django.db import models
from django.conf import settings
from django.urls import reverse
from django.db.models.signals import pre_save
from django.utils.text import slugify
from cloudinary.models import CloudinaryField
# Create your models here.
class ProductManager(models.Manager):
    def get_queryset(self):
        return super(ProductManager, self).get_queryset().filter(is_active=True)


class Category(models.Model):
    name = models.CharField(max_length=255, db_index=True)
    slug = models.SlugField(max_length=255, unique=True)
    image= CloudinaryField('image', folder="photoGear")
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now_add=True)

    class Meta :
        verbose_name_plural= 'Categories'
    
    def get_slug_field(self):
           return reverse('category_name', kwargs={'slug': self.slug}) 

    def get_absolute_url(self):
        return f'{self.slug}'

    def __str__(self):
        return self.name

    def get_category_url(self):
            if self.image:
                return  self.image.url

class Product(models.Model):
    category = models.ForeignKey(Category, related_name='products', on_delete=models.CASCADE)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='product_creator', on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    author = models.CharField(max_length=255, default='admin')
    description = models.TextField(blank=True)
    image= CloudinaryField('image', folder="photoGear/product")
    slug = models.SlugField(max_length=255, unique=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    in_stock = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()
    products = ProductManager()

    class Meta:
        verbose_name_plural = 'Products'
        ordering = ('-created',)

    def get_slug_field(self):
            return reverse('product_title', kwargs={'slug': self.slug}) 

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return f'/product/{self.category.slug}/{self.slug}/'
    
    def get_product_url(self):
        if self.image:
            return  self.image.url  

def slug_generator(sender,instance,*args,**kwargs) :
    slug = slugify(instance.title)

    exists = Product.objects.filter(slug=slug)
    if exists:
        slug= "%s-%s" %(slug,instance.slug)
    instance.slug = slug


 
pre_save.connect(slug_generator, sender=Product)
