using ImzaKit.Api.Operations;

namespace ImzaKit.DependencyInjection;

internal static class SignatureOperationResultExtensions
{
    public static bool OperationMutationSucceeded(this SignatureOperationResult result) =>
        result.Status is OperationMutationStatus.Succeeded or OperationMutationStatus.Replayed
        && result.Operation is not null;
}
