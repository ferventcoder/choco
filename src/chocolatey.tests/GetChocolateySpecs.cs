namespace chocolatey.tests
{
    using Moq;
    using Should;

    public class GetChocolateySpecs
    {
        public abstract class GetChocolateySpecsBase : TinySpec
        {
            protected GetChocolatey itemUnderTest;

            public override void Context()
            {
               // itemUnderTest = new GetChocolatey();
            }
        }

        public class when_GetChocolatey_is_called : GetChocolateySpecsBase
        {
            private GetChocolatey result;

            public override void Context()
            {
                base.Context();
            }

            public override void Because()
            {
                result = Lets.GetChocolatey();
            }

            [Fact]
            public void should_result_in()
            {
               // result.
            }
        }
    }
}
