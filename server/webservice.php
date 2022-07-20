<?php
    require_once "conexao.php";

    function certificarLogin(){
        global $conexao;
        if(isset($_COOKIE["token"], $_COOKIE["id_usuario"])){
            //verificando se os cookies são válidos
            $sql = "SELECT count(*) 'existe' FROM dispositivo WHERE token=:token AND fkusuario=:id_usuario AND NOW()<DATE_ADD(datacriacao, INTERVAL 30 DAY)";
            $comando = $conexao->prepare($sql);
            $comando->bindParam(":token", $_COOKIE["token"]);
            $comando->bindParam(":id_usuario", $_COOKIE["id_usuario"]);
            $comando->execute();
            $verificar = $comando->fetch(PDO::FETCH_ASSOC);
            if($verificar["existe"] == 1){
                return 1;
            }else{
                return 0;
            }

        }else{
            return 0;
        }
    }
//questao temporal do cookie
    $fim = time() + ((3600*24)*15);
    extract($_POST);
    $retorno = array();
    $navegador = $_SERVER["HTTP_USER_AGENT"];
    if (isset($tipo)) {
        if ($tipo == "logar" && isset($email_usuario, $senha_usuario)) {
            //logar
            $sql = "SELECT id_usuario, nome_usuario, senha_usuario FROM usuario WHERE email_usuario=:email_usuario";
            $cmd = $conexao->prepare($sql);
            $cmd->bindParam(":email_usuario", $email_usuario);
            $cmd->execute();
            $dados = $cmd->fetch(PDO::FETCH_ASSOC);
            if (isset($dados["id_usuario"])){
                //Usuario encontrado com o email_usuario indicado
                if (password_verify($senha_usuario, $dados["senha_usuario"])) {
                    //Caso a verificação for verdadeira, realiza o login
                    $retorno["status"] = 1;
                    $retorno["nome_usuario"] = $dados["nome_usuario"];
                    $retorno["id_usuario"] = $dados["id_usuario"];

                    $token = bin2hex(random_bytes(32));
                    $sqlDispositivo = "INSERT INTO dispositivo VALUES(0,:so,NOW(),:token,:fkusuario)";
                    $cmdDispositivo = $conexao->prepare($sqlDispositivo);
                    $cmdDispositivo->bindParam(":so",$navegador);
                    $cmdDispositivo->bindParam(":token",$token);
                    $cmdDispositivo->bindParam(":fkusuario",$dados["id_usuario"]);
                    $cmdDispositivo->execute();

                    setcookie("token", $token, $fim, "/arcadigital");
                    setcookie("id_usuario", $dados["id_usuario"], $fim, "/arcadigital");

                }else{
                    //senha_usuario incorreta
                $retorno["status"] = 0;
                $retorno["mensagem"] = "senha_usuario inválida";
                }
            }else{
                //Usuario não encontrado
                $retorno["status"] = 0;
                $retorno["mensagem"] = "Usuario não encontrado";
            }
            
        } else if($tipo == "cadastrar" && isset($email_usuario, $senha_usuario, $nome_usuario)){
            //cadastrar
            $sql = "INSERT INTO usuario VALUES(0, :nome_usuario, :email_usuario, :senha_usuario)";
            $senha_usuario = password_hash($senha_usuario, PASSWORD_DEFAULT);
            $cmd = $conexao->prepare($sql);
            $cmd->bindParam(":nome_usuario", $nome_usuario);
            $cmd->bindParam(":email_usuario", $email_usuario);
            $cmd->bindParam(":senha_usuario", $senha_usuario);
            if ($cmd->execute()) {
                $retorno["status"] = 1;
                $retorno["mensagem"] = "Cadastro realizado com sucesso";
            }
        }
        else if($tipo == "deslogar"){

            if(certificarLogin()){
                $sql = "DELETE FROM dispositivo WHERE fkusuario = :fkusuario AND token=:token";
                $comando = $conexao->prepare($sql);
                $comando->bindParam(":fkusuario", $_COOKIE["id_usuario"]);
                $comando->bindParam(":token", $_COOKIE["token"]);
                $comando->execute();
                setcookie("id_usuario", 0, time() - 1);
                setcookie("token", 0, time() - 1);
                $retorno["status"] = 1;
            }else{
                $retorno["status"] = 0;
            }
        } else if($tipo == "deslogar_todos"){

            if(certificarLogin()){
                $sql = "DELETE FROM dispositivo WHERE fkusuario = :fkusuario";
                $comando = $conexao->prepare($sql);
                $comando->bindParam(":fkusuario", $_COOKIE["id_usuario"]);
                $comando->execute();
                setcookie("id_usuario", 0, time() - 1);
                setcookie("token", 0, time() - 1);
                $retorno["status"] = 1;
            }else{
                $retorno["status"] = 0;
            }
        }
        else if($tipo == "verificar_token"){
            $retorno["status"] = certificarLogin();
        }
    }else {
        $retorno["status"] = 0;
        $retorno["mensagem"] = "Requisição inválida";
    }

    echo json_encode($retorno, JSON_UNESCAPED_UNICODE);

?>