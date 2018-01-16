<?php
use \Hcode\PageAdmin;
use \Hcode\Model\User;
use \Hcode\Model\Product;

$app->get("/admin/products", function(){
	
	User::VerifyLogin();

	$products = Product::listAll();

	$page =  new PageAdmin();

	$page->setTpl("Products",[
		"products"=>$products
	]);

});

$app->get("/admin/products/create", function(){
	
	User::VerifyLogin();

	$page =  new PageAdmin();

	$page->setTpl("Products-create");

});

$app->post("/admin/products/create", function(){
	
	User::VerifyLogin();

	$products = new Product();

	$Product->setData($_POST);

	$Product->save();

	header("location: /admin/products");
	exit;

});


?>