<?php

namespace Hcode\Model;

use \Hcode\DB\Sql;
use \Hcode\Model;
use \Hcode\Mailer;

class User extends Model {

	const SESSION = "User";

	const SECRET = "HcodePho7_Secret";

	public static function login($login,$password){

		$sql = new Sql();

		$results = $sql->select("SELECT  * FROM tb_users WHERE deslogin = :LOGIN",array(
			":LOGIN"=>$login
		));

		if(count($results) === 0){

			throw new \Exception("Usuário inexistente ou senha inválida");
		}

		$data = $results[0];

		if (password_verify($password, $data["despassword"]) === true){

			$user = new User();

			$user->setData($data);

			$_SESSION[User::SESSION] = $user->getValues();

			return $user;

		} else {

			throw new \Exception("Usuário inexistente ou senha inválida");
		}
	}

	public static function verifyLogin($inadmin = true){

		if(

			!isset($_SESSION[User::SESSION])
			||
			!$_SESSION[User::SESSION]
			||
			!(int)$_SESSION[User::SESSION]["iduser"] > 0
			||
    		(bool)$_SESSION[User::SESSION]["inadmin"] !== $inadmin

		){

			header("location: /admin/login");
			exit;

		}

	}

	public static function logout (){

		$_SESSION[User::SESSION] = NULL;
	}

	public static function listAll(){

		$sql =  new Sql();

		return $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) ORDER BY b.desperson");
	}


	public function save(){

		$sql = new Sql();
		/*
		pdesperson VARCHAR(64),
		pdeslogin VARCHAR(64),
		pdespassword VARCHAR(64),
		pdesemail VARCHAR(64),
		pnrphone BIGINT,
		pinadmin TINYNT
		*/
		$results = $sql->select("CALL sp_users_save(:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", 
			array(
			":desperson"=>$this->getdesperson(),
			":deslogin"=>$this->getdeslogin(),
			":despassword"=>$this->getdespassword(),
			":desemail"=>$this->getdesemail(),
			":nrphone"=>$this->getnrphone(),
			":inadmin"=>$this->getinadmin()

		));

		$this->setData($results[0]);
	}

	public function get($iduser){
     $sql = new Sql();
     $results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) WHERE a.iduser = :iduser", array(
         ":iduser"=>$iduser
     ));
     $data = $results[0];
     $data['desperson'] = utf8_encode($data['desperson']);
     $this->setData($data);
	}

	public function update(){

		$sql = new Sql();
		/*
		pdesperson VARCHAR(64),
		pdeslogin VARCHAR(64),
		pdespassword VARCHAR(64),
		pdesemail VARCHAR(64),
		pnrphone BIGINT,
		pinadmin TINYNT
		*/
		$results = $sql->select("CALL sp_usersupdate_save(:iduser, :desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", 
			array(
			":iduser"=>$this->getiduser(),	
			":desperson"=>$this->getdesperson(),
			":deslogin"=>$this->getdeslogin(),
			":despassword"=>$this->getdespassword(),
			":desemail"=>$this->getdesemail(),
			":nrphone"=>$this->getnrphone(),
			":inadmin"=>$this->getinadmin()

		));

		$this->setData($results[0]);
	}

	public function delete(){

		$sql = new Sql();

		$sql->query("CALL sp_users_delete(:iduser)", array(
			"iduser"=>$this->getiduser()
		));
	}

	public static function encrypt_decrypt($action, $string) {
        $output         = false;
        $encrypt_method = "AES-256-CBC";
        $secret_key     = 'This is my secret key';
        $secret_iv      = 'This is my secret iv';
        // hash
        $key = hash('sha256', $secret_key);
 
        // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
        $iv = substr(hash('sha256', $secret_iv), 0, 16);
        if ($action == 'encrypt') {
            $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
            $output = base64_encode($output);
        } else if ($action == 'decrypt') {
            $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
        }
        return $output;
    }
 
    /**
     * [getForgot] Verifica se o email digitado existe
     * se existir Envia o email para alteração de senha
     */
    public static function getForgot($email) {
 
        $sql     = new Sql();
        $results = $sql->select(
            "SELECT * FROM tb_persons a
            INNER JOIN tb_users b USING(idperson)
            WHERE a.desemail = :email",
            array(
                ":email" => $email,
            ));
 
        if (count($results) === 0) {
            throw new \Exception("Não foi possível recuperar a senha.");
        } else {
            $data     = $results[0];
            $results2 = $sql->select(
                "CALL sp_userspasswordsrecoveries_create(:iduser, :desip)",
                array(
                    ":iduser" => $data["iduser"],
                    ":desip"  => $_SERVER["REMOTE_ADDR"],
                ));
        }
 
        if (count($results2) === 0) {
            throw new \Exception("Não foi possível recuperar a senha.");
 
        } else {
            $dataRecovery = $results2[0];
 
            // Gerar código encripitado
            /*$plaintext = "message to be encrypted";// length=23
            $cipher    = "aes-128-gcm";// length=11
 
            if (in_array($cipher, openssl_get_cipher_methods())) {
            $ivlen = openssl_cipher_iv_length($cipher);
            $iv    = openssl_random_pseudo_bytes($ivlen);
            $code  = openssl_encrypt($plaintext, $cipher, $dataRecovery["idrecovery"], $options = 0, $iv, $tag);
            //store $cipher, $iv, and $tag for decryption later
            //$original_plaintext = openssl_decrypt($ciphertext, $cipher, $key, $options = 0, $iv, $tag);
            //echo $original_plaintext."\n";
            }*/
            $code = User::encrypt_decrypt('encrypt', $dataRecovery["idrecovery"]);
 
            $link   = "http://ecommerce.admin.dev/admin/forgot/reset?code=$code";
            $mailer = new Mailer(
                $data["desemail"],
                $data["desperson"],
                "Redefinir senha da Ecom",
                "forgot",
                array(
                    "name" => $data["desperson"],
                    "link" => $link,
                )
            );
 
            $mailer->send();// Envia o email
 
            return $data;// Dados do usuário
        }
 
    }
    public static function validForgotDecrypt($code) {
        var_dump($code);
 
        $idrecovery = User::encrypt_decrypt('decrypt', $code);
        var_dump($idrecovery);
 
        $sql     = new Sql();
        $results = $sql->select(
            "SELECT * FROM tb_userspasswordsrecoveries a
            INNER JOIN tb_users b USING(iduser)
            INNER JOIN tb_persons c USING(idperson)
            WHERE a.idrecovery = :idrecovery
            AND a.dtrecovery IS NULL
            AND DATE_ADD(a.dtregister, INTERVAL 1 HOUR) >= NOW()
            ", array(
                ":idrecovery" => $idrecovery,
            ));
 
        if (count($results) === 0) {
            throw new \Exception("Não foi possível recuperar a senha.");
 
        } else {
            return $results[0];
        }
    }
}


?>