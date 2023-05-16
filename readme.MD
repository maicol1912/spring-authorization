## Flujo aplicacion de seguridad

1. Un usuario intenta acceder a una página o recurso protegido en la aplicación web.

2. El filtro OncePerRequestFilter captura la solicitud del usuario antes de que llegue al controlador de Spring MVC.

3. Si la solicitud es para una página o recurso protegido, el filtro de autenticación AbstractAuthenticationProcessingFilter /*file: JwtUsernamePasswordAuthenticationFilter*/ se encarga de autenticar al usuario. Este filtro delega la autenticación en el proveedor de autenticación AuthenticationProvider. /*file: CustomAuthenticationProvider*/

4. Si el usuario es autenticado con éxito, se crea un objeto Authentication que contiene la información de autenticación del usuario y se lo guarda en el contexto de seguridad de Spring Security.

5. Si el usuario no puede ser autenticado, se lanza una excepción AuthenticationException y se le redirige a la página de inicio de sesión.

6. Después de la autenticación, se realiza la autorización. La autorización se basa en la configuración del control de acceso de la aplicación, que especifica qué usuarios o grupos de usuarios tienen acceso a diferentes partes de la aplicación. La autorización se realiza en los controladores de Spring MVC o en los métodos de servicio de la aplicación.

7. Si el usuario no tiene permiso para acceder a la página o recurso solicitado, se lanza una excepción AccessDeniedException y se le redirige a una página de acceso denegado.

8. La interfaz UserDetailsService se utiliza para cargar los detalles del usuario, como el nombre de usuario, la contraseña y los roles, desde la base de datos o cualquier otro origen de datos.

9. La interfaz UserDetailsService se utiliza para cargar los detalles del usuario, como el nombre de usuario, la contraseña y los roles, desde la base de datos o cualquier otro origen de datos.
