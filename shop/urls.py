from django.urls import path , include
from . import views
urlpatterns = [
    path('all-categories', views.getAllCategories, name='all-category'),
    path('products/<slug:category_slug>', views.getProducts, name='products'),
    path('product/<slug:product_slug>', views.getSingleProduct, name='all-product')
]