namespace ImzaKit.Api.Problems;

public sealed record ApiProblemDescriptor(int HttpStatus, string Code);
