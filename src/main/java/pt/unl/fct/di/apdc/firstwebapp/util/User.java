package pt.unl.fct.di.apdc.firstwebapp.util;

public class User{
    public String email,username,name,phone,password,perfil,cc,role,nif,employee,function,address,nifEmp,status,photo;

    public User(){}

    public User(String email, String username, String name, String phone,String password, String perfil){
        this.email = email;
        this.username = username;
        this.name = name;
        this.phone = phone;
        this.password = password;
        this.perfil = perfil;
        this.role = "enduser";
        this.status = "DESATIVADA";
    }

    public boolean isValid(){
        return email != null && username != null && name != null && phone != null && password != null && perfil != null;
    }
}