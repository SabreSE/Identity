using Microsoft.AspNetCore.Authorization;

namespace IdentityManagerServerApi.Permission
{
    internal class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
    {

        public PermissionAuthorizationHandler()
        {

        }


        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {
            if (context.User == null)
            {
                return;
            }
            var permissionss = context.User.Claims.Where(x => x.Type == "Permission" &&
                                                            x.Value == requirement.Permission &&
                                                            x.Issuer == "localhost");
            if (permissionss.Any())
            {
                context.Succeed(requirement);
                return;
            }
        }

        //protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        //{
        //    if (context.User == null)
        //    {
        //        return;
        //    }
        //    var permissionss = context.User.Claims.Where(x => x.Type == "Permission" &&
        //                                                    x.Value == requirement.Permission &&
        //                                                    x.Issuer == "LOCAL AUTHORITY");
        //    if (permissionss.Any())
        //    {
        //        context.Succeed(requirement);
        //        return;
        //    }
        //}
    }
}



//    internal class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
//    {
//        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
//        {
//            if (context.User == null)
//            {
//                return Task.CompletedTask;
//            }

//            // Check role requirement, if specified
//            bool roleRequirementMet = string.IsNullOrEmpty(requirement.RequiredRole) ||
//                                      context.User.IsInRole(requirement.RequiredRole);

//            // Check permission requirement
//            bool permissionRequirementMet = context.User.Claims.Any(x => x.Type == "Permission" &&
//                                                                         x.Value == requirement.Permission &&
//                                                                         (x.Issuer == "LOCAL AUTHORITY" || string.IsNullOrEmpty(x.Issuer)));

//            if (roleRequirementMet && permissionRequirementMet)
//            {
//                context.Succeed(requirement);
//            }

//            return Task.CompletedTask;
//        }
//    }
//}