namespace chocolatey.infrastructure.app.nuget
{
    using System.Collections.Generic;
    using NuGet;

    public interface IChocolateyServiceBasedRepository : IServiceBasedRepository
    {
        IEnumerable<string> GetMessageOfTheDay();
    }
}