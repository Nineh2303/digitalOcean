from django.db import models
from PhotoGear import settings
from shop.models import Product
from shop.serializers import ProductSerializer
# Create your models here.
class Cart(models.Model) :
    cartId = models.CharField(null=False, max_length=100,unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, related_name="carts")
    count = models.IntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    totalCart = models.DecimalField(max_digits=8 ,decimal_places=2, default=0 )
    ordered = models.BooleanField (default = False)
    class Meta: 
        ordering =["ordered"]
    def update(self):
        listItem = Item.objects.filter(cart=self)
        if(listItem is None) : 
            self.count=0 
        else:
            self.totalCart =0
            self.count=  listItem.count()
            for item in listItem:
                self.totalCart += item.totalPrice 
                
        self.save()
    def setOrdered(self):
        self.ordered = True 
        self.save()

    def __str__(self): 
        return self.cartId 


class Item(models.Model):
    cart=models.ForeignKey(Cart,on_delete=models.CASCADE, related_name="items")
    itemKey = models.CharField(null = True,max_length= 100)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="product")
    quantity = models.IntegerField(default=0)
    totalPrice= models.DecimalField(max_digits=10, decimal_places=2 , default=0)

    def getTotal(self): 
        self.totalPrice = self.product.price *self.quantity
        self.save()


class Order(models.Model) : 
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, related_name="orders")
    cart = models.ForeignKey(Cart,on_delete =models.SET_NULL, null= True, related_name="order")
    name = models.CharField(max_length=255, null= False)
    address = models.CharField(max_length=255 , null=False)
    numberPhone = models.CharField(max_length=15, null= False)
    shipped = models. BooleanField(default= False)

    class Meta: 
        ordering =["shipped"]
    def __str__(self):
        if (self.cart is None) : 
            return self.user.user_name + " - None Cart"
        return self.cart.cartId + " - User " + self.user.email