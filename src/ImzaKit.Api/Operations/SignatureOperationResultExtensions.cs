namespace ImzaKit.Api.Operations;

internal static class SignatureOperationResultExtensions
{
    public static bool OperationMutationSucceeded(this SignatureOperationResult result) =>
        result.Status is OperationMutationStatus.Succeeded or OperationMutationStatus.Replayed;
}
