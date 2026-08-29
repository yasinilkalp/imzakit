using ImzaKit.Api.Preservation;

namespace ImzaKit.Api.Tests.Preservation;

public sealed class PreservationSchedulerTests
{
    private static readonly TimeSpan Lead = TimeSpan.FromDays(30);
    private static readonly DateTimeOffset Now = new(2026, 8, 30, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ItemInsideLeadWindowIsDue()
    {
        PreservationObject item = Pades("a", Now.AddDays(10));

        Assert.True(PreservationScheduler.IsDue(item, Now, Lead));
        Assert.Contains(item, PreservationScheduler.SelectDue([item], Now, Lead));
    }

    [Fact]
    public void ItemOutsideLeadWindowIsNotDue()
    {
        PreservationObject item = Pades("a", Now.AddDays(90));

        Assert.False(PreservationScheduler.IsDue(item, Now, Lead));
        Assert.Empty(PreservationScheduler.SelectDue([item], Now, Lead));
    }

    [Fact]
    public void ExpiredArchiveTimestampIsDue()
    {
        PreservationObject item = Pades("a", Now.AddDays(-1));

        Assert.True(PreservationScheduler.IsDue(item, Now, Lead));
    }

    [Fact]
    public void RunRenewsOnlyDueItemsAndContinuesAfterFailure()
    {
        PreservationObject dueOk = Pades("ok", Now.AddDays(1));
        PreservationObject dueFail = Pades("fail", Now.AddDays(2));
        PreservationObject later = Pades("later", Now.AddDays(90));
        int calls = 0;
        PreservationRunResult run = PreservationScheduler.Run(
            [later, dueFail, dueOk],
            Now,
            Lead,
            item =>
            {
                calls++;
                return item.ObjectKey == "fail"
                    ? new PreservationRenewalResult(false, PreservationProblemCodes.Unavailable)
                    : new PreservationRenewalResult(true, NextNotAfterUtc: Now.AddYears(1));
            });

        Assert.Equal(2, calls);
        Assert.Equal(2, run.DueCount);
        Assert.Equal(1, run.RenewedCount);
        Assert.Equal(1, run.FailedCount);
        Assert.Contains(run.Items, item => item.ObjectKey == "ok" && item.Renewed);
        Assert.Contains(run.Items, item =>
            item.ObjectKey == "fail"
            && !item.Renewed
            && item.ProblemCode == PreservationProblemCodes.Unavailable);
        Assert.DoesNotContain(run.Items, item => item.ObjectKey == "later");
    }

    [Fact]
    public void UnsupportedFormatIsFailedWithoutCallingRenewer()
    {
        PreservationObject item = new("xades-1", "XAdES", Now.AddDays(1));
        bool called = false;

        PreservationRunResult run = PreservationScheduler.Run(
            [item],
            Now,
            Lead,
            _ =>
            {
                called = true;
                return new PreservationRenewalResult(true);
            });

        Assert.False(called);
        Assert.Equal(1, run.DueCount);
        Assert.Equal(0, run.RenewedCount);
        Assert.Equal(1, run.FailedCount);
        Assert.Equal(PreservationProblemCodes.UnsupportedFormat, run.Items[0].ProblemCode);
    }

    private static PreservationObject Pades(string objectKey, DateTimeOffset notAfter) =>
        new(objectKey, "PAdES", notAfter);
}
