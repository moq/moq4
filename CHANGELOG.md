# Moq Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).


## Unreleased

#### Added

* `SetupSet`, `VerifySet` methods for `mock.Protected().As<>()` (@tonyhallett, #1165)

#### Fixed

* Virtual properties and automocking not working for `mock.Protected().As<>()` (@tonyhallett, #1165)
* Issue mocking VB.NET class with overloaded property/indexer in base class (@myurashchyk, #1153)


## 4.16.1 (2021-02-23)

#### Added

* `CallBase` can now be used with interface methods that have a default interface implementation. It will call [the most specific override](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/proposals/csharp-8.0/default-interface-methods#the-most-specific-override-rule). (@stakx, #1130)

#### Changed

* Improved error message formatting of `It.Is` lambda expressions that capture local variables. (@bfriesen, #1140)

#### Fixed

* `AmbiguousMatchException` raised when interface has property indexer besides property in VB. (@mujdatdinc, #1129)
* Interface default methods are ignored (@hahn-kev, #972)
* Callback validation too strict when setting up a task's `.Result` property (@stakx, #1132)
* `setup.Returns(InvocationFunc)` wraps thrown exceptions in `TargetInvocationException` (@stakx, #1141)


## 4.16.0 (2021-01-16)

#### Added

* Ability to directly set up the `.Result` of tasks and value tasks, which makes setup expressions more uniform by rendering dedicated async verbs like `.ReturnsAsync`, `.ThrowsAsync`, etc. unnecessary:

   ```diff
   -mock.Setup(x => x.GetFooAsync()).ReturnsAsync(foo)
   +mock.Setup(x => x.GetFooAsync().Result).Returns(foo)
   ```

   This is useful in places where there currently aren't any such async verbs at all:

   ```diff
   -Mock.Of<X>(x => x.GetFooAsync() == Task.FromResult(foo))
   +Mock.Of<X>(x => x.GetFooAsync().Result == foo)
   ```

   This also allows recursive setups / method chaining across async calls inside a single setup expression:

   ```diff
   -mock.Setup(x => x.GetFooAsync()).ReturnsAsync(Mock.Of<IFoo>(f => f.Bar == bar))
   +mock.Setup(x => x.GetFooAsync().Result.Bar).Returns(bar)
   ```

   or, with only `Mock.Of`:

   ```diff
   -Mock.Of<X>(x => x.GetFooAsync() == Task.FromResult(Mock.Of<IFoo>(f => f.Bar == bar)))
   +Mock.Of<X>(x => x.GetFooAsync().Result.Bar == bar)
   ```

   This should work in all principal setup methods (`Mock.Of`, `mock.Setup…`, `mock.Verify…`). Support in `mock.Protected()` and for custom awaitable types may be added in the future. (@stakx, #1126)

#### Changed

* Attempts to mark conditionals setup as verifiable are once again allowed; it turns out that forbidding it (as was done in #997 for version 4.14.0) is in fact a regression. (@stakx, #1121)

#### Fixed

* Performance regression: Adding setups to a mock becomes slower with each setup (@CeesKaas, #1110)

* Regression: `mock.Verify[All]` no longer marks invocations as verified if they were matched by conditional setups. (@Lyra2108, #1114)


## 4.15.2 (2020-11-26)

#### Changed

* Upgraded `System.Threading.Tasks.Extensions` dependency to version 4.5.4 (@JeffAshton, #1108)


## 4.15.1 (2020-11-10)

#### Added

* New method overloads for `It.Is`, `It.IsIn`, and `It.IsNotIn` that compare values using a custom `IEqualityComparer<T>` (@weitzhandler, #1064)
* New properties `ReturnValue` and `Exception` on `IInvocation` to query recorded invocations return values or exceptions (@MaStr11, #921, #1077)
* Support for "nested" type matchers, i.e. type matchers that appear as part of a composite type (such as `It.IsAnyType[]` or `Func<It.IsAnyType, bool>`). Argument match expressions like `It.IsAny<Func<It.IsAnyType, bool>>()` should now work as expected, whereas they previously didn't. In this particular example, you should no longer need a workaround like `(Func<It.IsAnyType, bool>)It.IsAny<object>()` as originally suggested in #918. (@stakx, #1092)

#### Changed

* Event accessor calls (`+=` and `-=`) now get consistently recorded in `Mock.Invocations`. This previously wasn't the case for backwards compatibility with `VerifyNoOtherCalls` (which got implemented before it was possible to check them using `Verify{Add,Remove}`). You now need to explicitly verify expected calls to event accessors prior to `VerifyNoOtherCalls`. Verification of `+=` and `-=` now works regardless of whether or not you set those up (which makes it consistent with how verification usually works). (@80O, @stakx, #1058, #1084)
* Portable PDB (debugging symbols) are now embedded in the main library instead of being published as a separate NuGet symbols package (`.snupkg) (@kzu, #1098)

#### Fixed

* `SetupProperty` fails if property getter and setter are not both defined in mocked type (@stakx, #1017)
* Expression tree argument not matched when it contains a captured variable &ndash; evaluate all captures to their current values when comparing two expression trees (@QTom01, #1054)
* Failure when parameterized `Mock.Of<>` is used in query comprehension `from` clause (@stakx, #982)


## 4.15.0

This version was accidentally published as 4.15.1 due to an intermittent problem with NuGet publishing.


## 4.14.7 (2020-10-14)

#### Changed

* Mocks created by `DefaultValue.Mock` now inherit `SetupAllProperties` from their "parent" mock (like it says in the XML documentation) (@stakx, #1074)

#### Fixed

* Setup not triggered due to VB.NET transparently inserting superfluous type conversions into a setup expression (@InteXX, #1067)
* Nested mocks created by `Mock.Of<T>()` no longer have their properties stubbed since version 4.14.0 (@vruss, @1071)
* `Verify` fails for recursive setups not explicitly marked as `Verifiable` (@killergege, #1073)
* `Mock.Of<>` fails for COM interop types that are annotated with a `[CompilerGenerated]` custom attribute (@killergege, #1072)


## 4.14.6 (2020-09-30)

#### Fixed

* Regression since 4.14.0: setting nested non-overridable properties via `Mock.Of` (@mariotee, #1039)


## 4.14.5 (2020-07-01)

#### Fixed

* Regression since version 4.11.0: `VerifySet` fails with `NullReferenceException` for write-only indexers (@Epicycle23, #1036)


## 4.14.4 (2020-06-24)

#### Fixed

* Regression: `NullReferenceException` on subsequent setup if expression contains null reference (@IanYates83, #1031)


## 4.14.3 (2020-06-18)

#### Fixed

* Regression, Part II: `Verify` behavior change using `DefaultValue.Mock` (@DesrosiersC, #1024)


## 4.14.2 (2020-06-16)

#### Fixed

* Regression: `Verify` behavior change using `DefaultValue.Mock` (@DesrosiersC, #1024)


## 4.14.1 (2020-04-28)

#### Added

* New `SetupSequence` verbs `.PassAsync()` and `.ThrowsAsync(...)` for async methods with `void` return type (@fuzzybair, #993)

#### Fixed

* `StackOverflowException` on `VerifyAll` when mocked method returns mocked object (@hotchkj, #1012)


## 4.14.0 (2020-04-24)

#### Added

 * A mock's setups can now be inspected and individually verified via the new `Mock.Setups` collection and `IInvocation.MatchingSetup` property (@stakx, #984-#987, #989, #995, #999)

 * New `.Protected().Setup` and `Protected().Verify` method overloads to deal with generic methods (@JmlSaul, #967)

 * Two new public methods in `Times`: `bool Validate(int count)` and `string ToString()` (@stakx, 975)

#### Changed

 * Attempts to mark conditionals setup as verifiable are now considered an error, since conditional setups are ignored during verification. Calls to `.Verifiable()` on conditional setups are no-ops and can be safely removed. (@stakx, #997)

 * When matching invocations against setups, captured variables nested inside expression trees are now evaluated. Their values likely matter more than their identities. (@stakx, #1000)

#### Fixed

 * Regression: Restored `Capture.In` use in `mock.Verify(expression, ...)` to extract arguments of previously recorded invocations. (@vgriph, #968; @stakx, #974)

 * Consistency: When mocking a class `C` whose constructor invokes one of its virtual members, `Mock.Of<C>()` now operates like `new Mock<C>()`: a record of such invocations is retained in the mock's `Invocations` collection (@stakx, #980)

 * After updating Moq from 4.10.1 to 4.11, mocking NHibernate session throws a `System.NullReferenceException` (@ronenfe, #955)


## 4.13.1 (2019-10-19)

#### Fixed

* `SetupAllProperties` does not recognize property as read-write if only setter is overridden (@stakx, #886)

* Regression: `InvalidCastException` caused by Moq erroneously reusing a cached auto-mocked (`DefaultValue.Mock`) return value for a different generic method instantiation (@BrunoJuchli, #932)

* AmbiguousMatchException when setting up the property, that hides another one (@ishatalkin, #939)

* `ArgumentException` ("Interface not found") when setting up `object.ToString` on an interface mock (@vslynko, #942)

* Cannot "return" to original mocked type after downcasting with `Mock.Get` and then upcasting with `mock.As<>` (@pjquirk, #943)

* `params` arrays in recursive setup expressions are matched by reference equality instead of by structural equality (@danielcweber, #946)

* `mock.SetupProperty` throws `NullReferenceException` when called for partially overridden property (@stakx, #951)


## 4.13.0 (2019-08-31)

#### Changed

* Improved error message that is supplied with `ArgumentException` thrown when `Setup` or `Verify` are called on a protected method if the method could not be found with both the name and compatible argument types specified (@thomasfdm, #852).

* `mock.Invocations.Clear()` now removes traces of previous invocations more thoroughly by additionally resetting all setups to an "unmatched" state. (@stakx, #854)

* Consistent `Callback` delegate validation regardless of whether or not `Callback` is preceded by a `Returns`: Validation for post-`Returns` callback delegates used to be very relaxed, but is now equally strict as in the pre-`Returns` case.) (@stakx, #876)

* Subscription to mocked events used to be handled less strictly than subscription to regular CLI events. As with the latter, subscribing to mocked events now also requires all handlers to have the same delegate type. (@stakx, #891)

* Moq will throw when it detects that an argument matcher will never match anything due to the presence of an implicit conversion operator. (@michelcedric, #897, #898)

* New algorithm for matching invoked methods against methods specified in setup/verification expressions. (@stakx, #904)

#### Added

* Added support for setup and verification of the event handlers through `Setup[Add|Remove]` and `Verify[Add|Remove|All]` (@lepijohnny, #825) 

* Added support for lambda expressions while creating a mock through `new Mock<SomeType>(() => new SomeType("a", "b"))` and `repository.Create<SomeType>(() => new SomeType("a", "b"))`. This makes the process of mocking a class without a parameterless constructor simpler (compiler syntax checker...). (@frblondin, #884)

* Support for matching generic type arguments: `mock.Setup(m => m.Method<It.IsAnyType>(...))`. (@stakx, #908)

   The standard type matchers are:

   - `It.IsAnyType` &mdash; matches any type
   - `It.IsSubtype<T>` &mdash; matches `T` and proper subtypes of `T`
   - `It.IsValueType` &mdash; matches only value types

   You can create your own custom type matchers:

   ```csharp
   [TypeMatcher]
   class Either<A, B> : ITypeMatcher
   {
       public bool Matches(Type type) => type == typeof(A) || type == typeof(B);
   }
   ```

* In order to support type matchers (see bullet point above), some new overloads have been added to existing methods:

   - `setup.Callback(new InvocationAction(invocation => ...))`,  
     `setup.Returns(new InvocationFunc(invocation => ...))`:

      The lambda specified in these new overloads will receive an `IInvocation` representing the current invocation from which type arguments as well as arguments can be discovered.

   - `Match.Create<T>((object argument, Type parameterType) => ..., ...)`,  
     `It.Is<T>((object argument, Type parameterType) => ...)`:

      Used to create custom matchers that work with type matchers. When a type matcher is used for `T`, the `argument` received by the custom matchers is untyped (`object`), and its actual type (or rather the type of the parameter for which the argument was passed) is provided via an additional parameter `parameterType`. (@stakx, #908)

#### Fixed

* Moq does not mock explicit interface implementation and `protected virtual` correctly. (@oddbear, #657)

* `Invocations.Clear()` does not cause `Verify` to fail (@jchessir, #733)

* Regression: `SetupAllProperties` can no longer set up properties whose names start with `Item`. (@mattzink, #870; @kaan-kaya, #869)

* Regression: `MockDefaultValueProvider` will no longer attempt to set `CallBase` to true for mocks generated for delegates. (@dammejed, #874)

* `Verify` throws `TargetInvocationException` instead of `MockException` when one of the recorded invocations was to an async method that threw. (@Cufeadir, #883)

* Moq does not distinguish between distinct events if they have the same name (@stakx, #893)

* Regression in 4.12.0: `SetupAllProperties` removes indexer setups. (@stakx, #901)

* Parameter types are ignored when matching an invoked generic method against setups. (@stakx, #903)

* For `[Value]Task<object>`, `.ReturnsAsync(null)` throws `NullReferenceException` instead of producing a completed task with result `null` (@voroninp, #909)


## 4.12.0 (2019-06-20)

#### Changed

* Improved performance for `Mock.Of<T>` and `mock.SetupAllProperties()` as the latter now performs property setups just-in-time, instead of as an ahead-of-time batch operation. (@vanashimko, #826)
* Setups with no `.Returns(…)` nor `.CallBase()` no longer return `default(T)` for loose mocks, but a value that is consistent with the mock's `CallBase` and `DefaultValue[Provider]` settings. (@stakx, #849)

#### Added

* New method overload `sequenceSetup.ReturnsAsync(Func<T>)` (@stakx, #841)
* LINQ to Mocks support for strict mocks, i.e. new method overloads for `Mock.Of`, `Mocks.Of`, `mockRepository.Of`, and `mockRepository.OneOf` that accept a `MockBehavior` parameter. (@stakx, #842)

#### Fixed

* Adding `Callback` to a mock breaks async tests (@marcin-chwedczuk-meow, #702)
* `mock.SetupAllProperties()` now setups write-only properties for strict mocks, so that accessing such properties will not throw anymore. (@vanashimko, #836)
* Regression: `mock.SetupAllProperties()` and `Mock.Of<T>` fail due to inaccessible property accessors (@Mexe13, #845)
* Regression: `VerifyNoOtherCalls` causes stack overflow when mock setup returns the mocked object (@bash, #846)
* `Capture.In()` no longer captures arguments when other setup arguments do not match (@ocoanet, #844).
* `CaptureMatch` no longer invokes the capture callback when other setup arguments do not match (@ocoanet, #844).


## 4.11.0 (2019-05-28)

Same as 4.11.0-rc2. See changelog entries for the below two pre-release versions.


## 4.11.0-rc2 (2019-05-27)

This is a pre-release version.

#### Changed

* Debug symbols (`Moq.pdb`) have moved into a separate NuGet symbol package (as per the current official [guideline](https://docs.microsoft.com/en-us/nuget/create-packages/symbol-packages-snupkg)). If you want the Visual Studio debugger to step into Moq's source code, disable Just My Code, enable SourceLink, and configure [NuGet's symbol server](https://docs.microsoft.com/en-us/nuget/create-packages/symbol-packages-snupkg#nugetorg-symbol-server). (@stakx, #789)

#### Fixed

* Regression: Unhelpful exception message when setting up an indexer with `SetupProperty` (@stakx, #823)


## 4.11.0-rc1 (2019-04-19)

This is a pre-release version.

It contains several minor breaking changes, and there have been extensive internal rewrites in order to fix some very long-standing bugs in relation to argument matchers in fluent setup expressions.

#### Changed

* The library now targets .NET Standard 2.0 instead of .NET Standard 1.x. This has been decided based on the official [cross-platform targeting guideline](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/cross-platform-targeting) and the [End of Life announcement for .NET Core 1.x](https://devblogs.microsoft.com/dotnet/net-core-1-0-and-1-1-will-reach-end-of-life-on-june-27-2019/) (@stakx, #784, #785)
* Method overload resolution may change for:
    - `mock.Protected().Setup("VoidMethod", ...)`
    - `mock.Protected().Verify("VoidMethod", ...)`
    - `mock.Protected().Verify<TResult>("NonVoidMethod", ...)`

   due to a new overload: If the first argument is a `bool`, make sure that argument gets interpreted as part of `args`, not as `exactParameterMatch` (see also *Added* section below). (@stakx & @Shereef, #751, #753)
* `mock.Verify[All]` now performs a more thorough error aggregation. Error messages of inner/recursive mocks are included in the error message using indentation to show the relationship between mocks. (@stakx, #762)
* `mock.Verify` no longer creates setups, nor will it override existing setups, as a side-effect of using a recursive expression. (@stakx, #765)
* More accurate detection of argument matchers with `SetupSet` and `VerifySet`, especially when used in fluent setup expressions or with indexers (@stakx, #767)
* `mock.Verify(expression)` error messages now contain a full listing of all invocations that occurred across all involved mocks. Setups are no longer listed, since they are completely irrelevant in the context of call verification. (@stakx, #779, #780)
* Indexers used as arguments in setup expressions are now eagerly evaluated, like all other properties already are (except when they refer to matchers) (@stakx, #794)
* Update package reference to `Castle.Core` (DynamicProxy) from version 4.3.1 to 4.4.0 (@stakx, #797)

#### Added

* New method overloads:
   - `mock.Protected().Setup("VoidMethod", exactParameterMatch, args)`
   - `mock.Protected().Verify("VoidMethod", times, exactParameterMatch, args)`
   - `mock.Protected().Verify<TResult>("NonVoidMethod", times, exactParameterMatch, args)`

   having a `bool exactParameterMatch` parameter. Due to method overload resolution, it was easy to think this already existed when in fact it did not, leading to failing tests. (@Shereef & @stakx, #753, #751)
* Ability in `mock.Raise` and `setup.Raises` to raise events on sub-objects (inner mocks) (@stakx, #772)

#### Removed

* Pex interop (which has not been maintained for years). You might notice changes when using Visual Studio's IntelliTest feature. (@stakx, #786)

#### Fixed

* Setting multiple indexed object's property directly via LINQ fails (@TylerBrinkley, #314)
* `InvalidOperationException` when specifiying setup on mock with mock containing property of type `Nullable<T>` (@dav1dev, #725)
* `Verify` gets confused between the same generic and non-generic signature (@lepijohnny, #749)
* Setup gets included in `Verify` despite being "unreachable" (@stakx, #703)
* `Verify` can create setups that cause subsequent `VerifyAll` to fail (@stakx & @lepijohnny, #699)
* Incomplete stack trace when raising an event with `mock.Raise` throws (@MutatedTomato, #738)
* `Mock.Raise` only raises events on root object (@hallipr, #166)
* Mocking indexer captures `It.IsAny()` as the value, even if given in the indexer argument (@idigra, #696)
* `VerifySet` fails on non-trivial property setup (@TimothyHayes, #430)
* Use of `SetupSet` 'forgets' method setup (@TimothyHayes, #432)
* Recursive mocks don't work with argument matching (@thalesmello, #142)
* Recursive property setup overrides previous setups (@jamesfoster, #110)
* Formatting of enumerable object for error message broke EF Core test case (@MichaelSagalovich, #741)
* `Verify[All]` fails because of lazy (instead of eager) setup argument expression evaluation (@aeslinger, #711)
* `ArgumentOutOfRangeException` when setup expression contains indexer access (@mosentok, #714)
* Incorrect implementation of `Times.Equals` (@stakx, #805)


## 4.10.1 (2018-12-03)

#### Fixed

* `NullReferenceException` when using `SetupSet` on indexers with multiple parameters (@idigra, #694)
* `CallBase` should not be allowed for delegate mocks (@tehmantra, #706)

#### Changed

* Dropped the dependency on the `System.ValueTuple` NuGet package, at no functional cost (i.e. value tuples are still supported just fine) (@stakx, #721)
* Updated failure messages to show richer class names (@powerdude, #727)
* Upgraded `System.Reflection.TypeExtensions` and `System.Threading.Tasks.Extensions` dependencies to versions 4.5.1 (@stakx, #729)


## 4.10.0 (2018-09-08)

#### Added

* `ExpressionCompiler`: An extensibility point for setting up alternate LINQ expression tree compilation strategies (@stakx, #647)
* `setup.CallBase()` for `void` methods (@stakx, #664)
* `VerifyNoOtherCalls` for `MockRepository` (@BlythMeister, #682)

#### Changed

* Make `VerifyNoOtherCalls` take into account previous calls to parameterless `Verify()` and `VerifyAll()` (@stakx, #659)
* **Breaking change:** `VerifyAll` now succeeds after a call to `SetupAllProperties` even when not all property accessors were invoked (stakx, #684)

#### Fixed

* More precise `out` parameter detection for mocking COM interfaces with `[in,out]` parameters (@koutinho, #645)
* Prevent false 'Different number of parameters' error with `Returns` callback methods that have been compiled from `Expression`s (@stakx, #654)
* `Verify` exception should report configured setups for delegate mocks (@stakx, #679)
* `Verify` exception should include complete call expression for delegate mocks (@stakx, #680)
* Bug report #556: "Recursive setup expression creates ghost setups that make `VerifyAll` fail" (@stakx, #684)
* Bug report #191: "Upgrade from 4.2.1409.1722 to 4.2.1507.0118 changed `VerifyAll` behavior" (@stakx, #684)


## 4.9.0 (2018-07-13)

#### Added

* Add `Mock.Invocations` property to support inspection of invocations on a mock (@Tragedian, #560)

#### Changed

* Update package reference to `Castle.Core` (DynamicProxy) from version 4.3.0 to 4.3.1 (@stakx, #635)
* Floating point values are formatted with higher precision (satisfying round-tripping) in diagnostic messages (@stakx, #637)

#### Fixed

* `CallBase` disregarded for some base methods from non-public interfaces (@stakx, #641)

#### Obsoleted

* `mock.ResetCalls()` has been deprecated in favor of `mock.Invocations.Clear()` (@stakx, #633)


## 4.8.3 (2018-06-09)

#### Added

* Add `ISetupSequentialResult<TResult>.Returns` method overload that support delegate for deferred results (@snrnats, #594)
* Support for C# 7.2's `in` parameter modifier (@stakx, #624, #625)
* Missing methods `ReturnsAsync` and `ThrowsAsync` for sequential setups of methods returning a `ValueTask` (@stakx, #626) 

#### Changed

* **Breaking change:** All `ReturnsAsync` and `ThrowsAsync` setup methods now consistently return a new `Task` on each invocation (@snrnats, #595) 
* Speed up `Mock.Of<T>()` by approx. one order of magnitude (@informatorius, #598)
* Update package reference to `Castle.Core` (DynamicProxy) from version 4.2.1 to 4.3.0 (@stakx, #624)

#### Fixed

*  Usage of `ReturnsExtensions.ThrowsAsync()` can cause `UnobservedTaskException` (@snrnats, #595)
*  `ReturnsAsync` and `ThrowsAsync` with delay parameter starts timer at setup (@snrnats, #595)
*  `Returns` regression with null function callback (@Caraul, #602)


## 4.8.2 (2018-02-23)

#### Changed

* Upgraded `System.ValueTuple` dependency to version 4.4.0 in order to reestablish Moq compatibility with .NET 4.7 (and later), which already include the `ValueTuple` types (@stakx, #591)

#### Fixed

* Wrong parameters count for extension methods in `Callback` and `Returns` (@Caraul, #575)
* `CallBase` regression with members of additional interfaces (@stakx, #583)


## 4.8.1 (2018-01-08)

#### Added

* C# 7 tuple support for `DefaultValue.Empty` and `DefaultValue.Mock` (@stakx, #563)

#### Changed

* Downgraded `System.Threading.Tasks.Extensions` and `System.ValueTuple` dependencies to versions 4.3.0 as suggested by @tothdavid in order to improve Moq compatibility with .NET 4.6.1 / help prevent `MissingMethodException` and similar (@stakx, #571)

#### Fixed

* `CallBase` regression with explicitly implemented interface methods (@stakx, #558)


## 4.8.0 (2017-12-24)

Same as 4.8.0-rc1 (see below), plus some significant speed improvements.

#### Changed

* `SetupAllProperties` now fully supports property type recursion / loops in the object graph, thanks to deferred property initialization (@stakx, #550)


## 4.8.0-rc1 (2017-12-08)

This is a pre-release version.

#### Added

* Support for sequential setup of `void` methods (@alexbestul, #463)
* Support for sequential setups (`SetupSequence`) of protected members (@stakx, #493)
* Support for callbacks for methods having `ref` or `out` parameters via two new overloads of `Callback` and `Returns` (@stakx, #468)
* Improved support for setting up and verifying protected members (including generic methods and methods having by-ref parameters) via the new duck-typing `mock.Protected().As<TAnalog>()` interface (@stakx, #495, #501)
* Support for `ValueTask<TResult>` when using the `ReturnsAsync` extension methods, similar to `Task<TResult>` (@AdamDotNet, #506)
* Special handling for `ValueTask<TResult>` with `DefaultValue.Empty` (@stakx, #529)
* Support for custom default value generation strategies besides `DefaultValue.Empty` and `DefaultValue.Mock`:
  Implement custom providers by subclassing either `DefaultValueProvider` or `LookupOrFallbackDefaultValueProvider`,
  install them by setting `Mock[Repository].DefaultValueProvider` (@stakx, #533, #536)
* Allow `DefaultValue.Mock` to mock `Task<TMockable>` and `ValueTask<TMockable>` (@stakx, #502)
* Match any value for `ref` parameters with `It.Ref<T>.IsAny` (or `ItExpr.Ref<T>.IsAny` for protected methods) as you would with `It.IsAny<T>()` for regular parameters (@stakx, #537) 
* `Mock.VerifyNoOtherCalls()` to check whether all expected invocations have been verified -- can be used as an alternative to `MockBehavior.Strict` (@stakx, #539)

#### Changed

* **Breaking change:** `SetupSequence` now overrides pre-existing setups like all other `Setup` methods do. This means that exhausted sequences no longer fall back to previous setups to produce a "default" action or return value. (@stakx, #476)
* Delegates passed to `Returns` are validated a little more strictly than before (return type and parameter count must match with method being set up) (@stakx, #520)
* Change assembly versioning scheme to `major.minor.0.0` to help prevent assembly version conflicts and to reduce the need for binding redirects (@stakx, #554)

#### Fixed

* Update a method's invocation count correctly, even when it is set up to throw an exception (@stakx, #473)
* Sequences set up with `SetupSequence` are now thread-safe (@stakx, #476)
* Record calls to methods that are named like event accessors (`add_X`, `remove_X`) so they can be verified (@stakx, #488)
* Improve recognition logic for sealed methods so that `Setup` throws when an attempt is made to set one up (@stakx, #497)
* Let `SetupAllProperties` skip inaccessible methods (@stakx, #499)
* Prevent Moq from relying on a mock's implementation of `IEnumerable<T>` (@stakx, #510)
* Verification leaked internal `MockVerificationException` type; remove it (@stakx, #511)
* Custom matcher properties not printed correctly in error messages (@stakx, #517)
* Infinite loop when invoking delegate in `Mock.Of` setup expression (@stakx, #528) 

#### Obsoleted

* `[Matcher]` has been deprecated in favor of `Match.Create` (@stakx, #514)


## 4.7.145 (2017-11-06)

#### Changed

* Moq no longer collects source file information for verification error messages by default. A current .NET Framework regression (https://github.com/Microsoft/dotnet/issues/529) makes this extremely costly, so this is now an opt-in feature; see `Switches.CollectSourceFileInfoForSetups` (@stakx, #515)

#### Added

* `Mock.Switches` and `MockRepository.Switches`, which allow opting in and out of certain features (@stakx, #515)


## 4.7.142 (2017-10-11)

#### Changed

* Update package reference to `Castle.Core` (DynamicProxy) from version 4.2.0 to 4.2.1 due to a regression; see castleproject/Core#309 for details (@stakx, #482)

#### Fixed

* `TypeLoadException`s ("Method does not have an implementation") caused by the regression above, see e.g. #469 (@stakx, #482)


## 4.7.137 (2017-09-30)

#### Changed

* Update package reference to `Castle.Core` (DynamicProxy) from version 4.1.1 to 4.2.0, which uses a new assembly versioning scheme that should eventually reduce assembly version conflicts and the need for assembly binding redirects (@stakx, #459)

#### Fixed

* `mock.Object` should always return the exact same proxy object, regardless of whether the mock has been cast to an interface via `.As<T>()` or not (@stakx, #460)


## 4.7.127 (2017-09-26)

#### Changed

* Make setups for inaccessible internal members fail fast by throwing an exception (@stakx, #455)

#### Removed

* The redundant type `ObsoleteMockException` has been removed (@stakx)

#### Fixed

* Make `SetupAllProperties` work correctly for same-typed sibling properties (@stakx, #442)
* Switch back from portable PDBs to classic PDBs for better compatibility of SourceLink with older .NET tools (@stakx, #443)
* Make strict mocks recognize that `.CallBase()` can set up a return value, too (@stakx, #450)


## 4.7.99 (2017-07-17)

#### Added

* Add `[NeutralResourcesLanguage]` to assembly info for portable library use (@benbillbob, #394)
* Add portable, [SourceLink](https://github.com/ctaggart/SourceLink)-ed debugging symbols (PDB) to NuGet package, enabling end users to step into Moq's source code (@stakx, #417)

#### Changed

* Move all hardcoded message strings to `Resources.resx` (@stakx, #403)
* Update package reference to `Castle.Core` (DynamicProxy) from version 4.1.0 to 4.1.1 (@stakx, #416)
* Clean up and simplify the build process by merging separate .NET Framework and .NET Standard projects (@stakx, #417)
* Replace outdated `ReleaseNotes.md` with new `CHANGELOG.md` (@stakx, #423)

#### Fixed

* Fix member name typo in reflection code (@JohanLarsson, #389)
* Make `Interceptor` more thread-safe during `mock.Setup` (@stakx, #392)
* Make abstract events defined in classes work even when `CallBase` is true by suppressing `InvokeBase()` (@stakx, #395)
* Allow setting up null return values using `Mock.Of` (@stakx, #396)
* Allow `Mock<T>.Raise` to raise events on child mocks instead of raising no or the wrong event (@stakx, #397)
* Improve specificity of `Setup` / `Verify` exception messages for static members and extension methods (@stakx, #400)
* Prevent internal interception on a mock from changing its `DefaultValue` property (@vladonemo, #411)
* Prevent stack overflow in conditional setups (@stakx, #412)
* Fix `NullReferenceException` caused by internally relying on a mock's `IEnumerable` implementation (@stakx, #413)
* Improve method match accuracy in `ExtractProxyCall` so that the order of setting up methods in an hierarchy of interfaces does not matter (@stakx, #415) 
* Improve mockability of C++/CLI interfaces having custom modifiers (`modopt`, `modreq`) in their method signatures (@stakx, #416)
* Make types implementing the same generic type more than two times mockable (@stakx, #416)
* Fix misreported `Times` in verification error messages (@stakx, #417)


## 4.7.63 (2017-06-21)

#### Changed

* Ensure that `null` never matches an `It.IsRegex(…)` (@stakx, #385)

#### Fixed

* Fix mocking of non-virtual methods via `mock.As<TInterface>()` which was broken by #381 (@stakx, #387) 


## 4.7.58 (2017-06-21)

#### Fixed

* Fix formatting inconsistencies for array values in `MockException.Message` (@stakx, #380)
* Fix major "class method vs. interface method" bug introduced by #119 / commit 162a543 (@stakx, #381)
* Fix mocking for redeclared interface properties (get-set but get-only in base type) (@stakx, #382)


## 4.7.49 (2017-06-18)

#### Fixed

* Fix incorrect Castle.Core package reference in NuGet package specification (@stakx, #379)


## 4.7.46 (2017-06-18)

#### Changed

* Extend `EmptyDefaultValueProvider` so it understands multidimensional arrays (return empty multidimensional arrays instead of `null`) (@stakx, #360)
* Update package reference to `Castle.Core` (DynamicProxy) from version 4.0.0 to 4.1.0, update `System` and `Microsoft` packages from versions 4.0.1 to 4.3.0 (@stakx, #369)
* Clean up and reduce usage of conditional compilation (`#if`) (@stakx, #378)

#### Fixed

* Ensure default mock names are (more) unique (@stakx, #359)
* Make `It.IsAny`, `It.IsNotNull` work for COM types (@stakx, #361)
* Fix equality check bug in `ExpressionKey` which meant Moq would sometimes ignore exact argument order in setups (@kostadinmarinov, #135; @stakx, #363)
* Ensure incorrect implementations of `ISerializable` are caught properly (@stakx, #370)
* Make event accessor recognition logic more correct (don't just rely on `add_` or `remove_` name prefixes) (@stakx, #376)


## 4.7.25 (2017-06-03)

#### Added

* Add new `setup.ReturnsAsync` and `setup.ThrowsAsync` overloads allowing you to specify a delay (@jochenz, #289)

#### Changed

* Migrate .NET Core project to the new `.csproj` format (@jeremymeng, #336)


## 4.7.12 (2017-05-30)

#### Fixed

* Add overload in `mock.Protected()` setups to enforce the old behavior of exact parameter matching (new behavior fails for specific overloads) (@80er, #347)


## 4.7.11 (2017-05-30)

Minor change only (fix typo in documentation)


## 4.7.10 (2017-05-10)

Minor change only (update project URL in NuGet package metadata)


## 4.7.9 (2017-04-29)

Minor change only (add download badge to `README.md`)


## 4.7.8 (2017-03-26)

Minor change only (update license URL in NuGet package metadata)


## 4.7.7 (2017-03-25)

#### Fixed

* Allow setting up of protected methods with nullable parameters (@RobSiklos, #200)
* Fix incorrect code example in XML documentation comment for `Mock.Verify` (@jcockhren, #333)
* Fix bug in `HasMatchingParameterTypes` which caused `Protected().Verify` to reject valid mocks (@jeremymeng, #335)


## 4.7.1 (2017-02-28)

Minor change only (fix typo in documentation)


## 4.7.0 (2017-02-22)

Minor change only (correcting Moq version after semver violation)
This version is the successor of 4.6.62-alpha.


## 4.6.62-alpha (2017-02-21)

This version is the predecessor of 4.7.0 and essentially a cleaned up merge of both 4.5.30 and 4.6.39-alpha.


----

**Note:** The release notes for some Moq versions 4.6.*-alpha are still missing. They need to be
reconstructed from the commit history and the GitHub issue archive. If you would like to help make
this changelog more complete, any pull requests towards that goal are appreciated!

----


## 4.5.30 (2017-01-09)

#### Fixed

* Fix issue in `ExpressionKey` that caused identical setups to no longer be considered the same (@MatKubicki, #313)


## 4.5.29 (2016-12-10)

#### Fixed

* Make the recently added `setup.ReturnsAsync(Func<TResult> result)` evaluate its argument lazily, like `setup.Returns` would (@SaroTasciyan, #309)


## 4.5.28 (2016-11-11)

#### Added

* New method `setup.ReturnsAsync(Func<TResult> result)` (@joeenzminger, @tlycken, #297)


## 4.5.23 (2016-10-11)

#### Fixed

* Improves comparison of call arguments in `ExpressionKey` so that setups for the same method but with differing arguments don't override each other (@MatKubicki, #291)


## 4.5.22 (2016-09-20)

#### Fixed

* Properly raise events when mocked type implements multiple interfaces (@bradreimer, #288)


## 4.5.21 (2016-08-12)

#### Fixed

* Fix `mock.Reset()` which so far forgot to also clear all existing calls in the interceptor (@anilkamath87, #277)


## 4.5.20 (2016-08-12)

#### Fixed

* Ensure that mocking of `System.Object` methods always works, even in strict mode (again) (@kolomanschaft, #280)


## 4.5.19 (2016-08-10)

#### Fixed

* Make `SetupAllProperties` work with `DefaultValue.Mock` in the presence of object graph loops (i.e. when a type contains a property having the same type) (@vladonemo, #245)
* Prevent invalid implementations of `ISerializable` from being mocked (as DynamicProxy cannot handle these) via the new `SerializableTypesValueProvider` decorator (@vladonemo, #245)


## 4.5.18 (2016-08-10)

#### Fixed

* Ensure that mocking of `System.Object` methods always works, even in strict mode (@kolomanschaft, #279)


## 4.5.16 (2016-07-18)

#### Added

* Allow mocking of `System.Object` methods (`ToString`, `Equals`, and `GetHashCode`) (@kolomanschaft, #250)


## 4.5.13 (2016-07-11)

#### Changed

* `Verify` exception messages should include actual array values for specific calls instead of just `T[]` or variable names (@hahn-kev, #264)


## 4.5.10 (2016-06-21)

#### Added

* Add helper classes `Capture`, `CaptureMatch<T>` to simplify parameter capture (@ocoanet, #251)


## 4.5.9 (2016-06-09)

Minor change only (remove download badge from `README.md`)


## 4.5.8 (2016-05-26)

Minor change only (add `.editorconfig` file)


## 4.5.7 (2016-05-26)

#### Changed

* Reference Castle.Core as a NuGet package dependency instead of ILMerge-ing it into Moq's own assembly. (@kzu)
* Update package reference to `GitInfo` from version 1.1.14 to 1.1.15 to fix versioning issue with cached Git info (@kzu)

#### Removed

* Remove debugging symbols (PDB) from package since GitLink doesn't seem to be working (@kzu)


## 4.5.3 (2016-05-26)

#### Added

* New helper methods `Mock.Verify(params Mock[] mocks)` and `Mock.VerifyAll(...)` (@RehanSaeed, #238)


## 4.5.0 (2016-05-24)

Minor change only (update release notes in NuGet package metadata)
This version is the successor of 4.5.9-alpha.

## 4.5.9-alpha (2016-05-22)

This version is the predecessor of 4.5.0.

#### Fixed

* Fix broken hashing in `ExpressionKey` that causes Moq to not be able to distinguish method setups differing only in the exact argument order (@LeonidLevin, #262)


## 4.5.7-alpha (2016-05-22)

#### Removed

* Remove (for the time being) official statement in release notes that Moq supports .NET Core (@kzu)


## 4.5.6-alpha (2016-05-22)

#### Added

* Add `ReturnsAsync` and `ThrowsAsync` methods for sequential values setups (@abatishchev, #261)

#### Changed

* Migrate to .NET 4.5 and NuGet 3 (@kzu)
* Update package reference to `GitInfo` from version 1.1.13 to 1.1.14 (@kzu)

### Removed

* Remove COM unit tests (@kzu)
* Remove legacy Silverlight unit test project (@kzu)
* Remove `[NeutralResourcesLanguage]` attribute from main assembly (@kzu)

#### Fixed

* Avoid race conditions / improve thread safety of `MockDefaultValueProvider` (@mizbrodin, #207)
* Fix a code typo in `ExpressionComparer` (@AppChecker, #242)
* When mocking delegates, copy parameter attributes so `out` parameters work correctly (@urasandesu, #255)


## 4.2.1510.2205 (2015-10-22)

#### Added

* Add Gitter badge to `README.md` (@kzu)

#### Changed

* Upgrade to Castle.Core version 3.3.3 (@MSK61, @kzu, #204)

#### Fixed

* Make Task Parallel Library (TPL) code Silverlight 5 compatible (@iskiselev, #148)
* Fox license hyperlink so it points to correct version of the BSD license (@chkpnt, #198)


## 4.2.1507.118 (2015-06-29)

#### Fixed

* Move Silverlight 5 assemblies in proper `lib\sl5` folder (instead of `lib\sl4`) in the NuGet package (@kzu)


## 4.2.1506.2515 (2015-06-25)

#### Added

* Add new `mock.Reset()` extension method (@ashmind, #138)

#### Fixed

* Allow `null` to match nullable value types (@pkpjpm, #185)


## 4.2.1506.2016 (2015-06-20)

#### Added

* Add NuGet badges to `README.md` (@kzu)
* Add generic type argument information in exception messages for easier debugging (@hasaki, #177)

#### Changed

* Migrate Silverlight support from version 4 to 5 (@kzu) 
* Upgrade source code to Visual Studio 2013 (@kzu)

#### Fixed

* Fix `NullReferenceException` when passing `null` to a nullable argument but trying to match it with a non-nullable `IsAny` (@benjamin-hodgson, #160)
* Fix infinite loop when calling `SetupAllProperties` for entities with a hierarchy (@Moq, #180)


## 4.2.1502.911 (2015-02-09)

#### Fixed

* `SetupAllProperties` doesn't setup properties that don't have a setter (@NGloreous, #137)
* Fix DynamicProxy-related `NotImplementedException` when mocking interfaces with `CallBase = true` (@rjasica, #145)


## 4.2.1409.1722 (2014-09-17) / 4.2.1408.717 (2014-08-07)

Minor change only (update NuGet metadata)
This version was released twice under different version numbers.


## 4.2.1408.619 (2014-08-06)


#### Changed

* Migrate to MSBuild version 12 (@kzu)
* Enable `mock.As<TInterface>()` syntax for all implemented interfaces (except COM interfaces) even after `mock.Object` has been called (@scott-xu, #119, #123)

#### Deprecated

* Change `README.md` to show the use of `AtMostOnce` in `Verify` phase instead of `Setup` phase (@kzu)

#### Fixed

* Ordered call issue with invocations with same arguments in `MockSequence` (@drieseng, #97)
* Update various hyperlinks in `README.md` (@kzu)
* Improve Moq's support for curried delegates and fix failing unit tests when compiling Moq with Roslyn (@theoy, #125)


## 4.2.1402.2112 (2014-02-21)

#### Added

* Allow mocks to have names (@pimterry, #76, #83)

#### Changed

* Make `InterfaceProxy` class publicly visible to reenable mocking of interfaces (@pimterry, #99)

#### Removed

* Remove commercial licenses offer in `README.md` (@kzu)

#### Fixed

* Improve thread safety by splitting the interceptor's context into global one and one for the current proxy invocation only (@MatKubicki, #80)


## 4.2.1312.1622 (2013-12-16)

#### Fixed

* Improve thread safety in `Interceptor` and fix multithreading tests (@MatKubicki, #68)


## 4.2.1312.1621 (2013-12-16)

#### Fixed

* Fix `NullReferenceException` when trying to get a default value for `Task<T>` when `T` is a reference type (@alextercete, #73)


## 4.2.1312.1615 (2013-12-16)

Minor change only (update release notes)


## 4.2.1312.1416 (2013-12-14)

#### Changed

* `InSequence` setups can now be used on the same mock instance (@halllo, #72)


## 4.2.1312.1323 (2013-12-13)

#### Changed

* Move extension methods in class `Moq.Language.Flow.IReturnsExtensions` to `Moq.ReturnsExtensions` for better discoverability (@jdom, #71)


## 4.2.1312.1319 (2013-12-13)

#### Added

* Add `ReturnsAsync` and `ThrowsAsync` setup methods for better async support (@Blewzman, #60) 
* Migrate `README.md` content from Google Code (@kzu)

#### Changed

* Change `EmptyDefaultValueProvider` so it does not return `null` for `Task` and `Task<T>` types, but completed, awaitable tasks (@alextercete, #66)


## 4.1.1311.615 (2013-11-06)

#### Added

* Add `Throws` method to sequential value setups for testing retry logic in web services (@kellyselden, #59)

#### Fixed

* Matchers should not ignore implicit type conversions (@svick, #56)


## 4.1.1309.1617 (2013-09-16) / 4.1.1309.919 (2013-09-09)

This version was released twice under different version numbers.

#### Fixed

* Fix regression bug surrounding `Mock.As<TInterface>()`: Prevent early initialization of mock from checking for delegate mocks. (@kzu, #54)


## 4.1.1309.801 (2013-09-08)

#### Added

* Allow resetting of all call counts (those that will be compared with `Times`) (@salfab, #55)


## 4.1.1309.800 (2013-09-08) / 4.1.1308.2321 (2013-08-23)

This version was released twice under different version numbers.

#### Added

* New `It.IsNotNull<T>` matcher (@Pjanssen, #40)
* Add covariant `IMock<out T>` interface to `Mock<T>` (@tkellogg, #44)

#### Changed

* Rename `Changelog.txt` to `ReleaseNotes.md` and inject the latter into the NuGet metadata (@Moq, #52)

#### Fixed

* Fix "collection modified" exception thrown as result of more methods being called on a mock while verifying method calls (@yonahw, #36)
* Fix `NullReferenceException` when subscribing to an event (@bittailor, #39)
* Fix thread safety issue (`IndexOutOfRangeException`) on setup (@stoo101, #51)


## 4.1.1308.2316

Minor change only (change title in NuGet package metadata)


## 4.1.1308.2120

#### Added

* Add capability for mocking delegates (event handlers) (@quetzalcoatl, #4)
* Allow `CallBase` for specific method / property (@srudin, #8)
* New matchers `It.IsIn` and `It.IsNotIn` (@rdingwall, #27)
* Add `.gitignore` file (@yorah, #10 / @FellicePollano, #30)
* Add new `Verify` method overload group that accepts a `Times` instance (@ChrisMissal, #34)

#### Changed

* Update Castle.Core assemblies from version 1.2.0.0 to 3.2.0, fetch Castle.Core via NuGet (@yorah, #11 / @kzu)
* Corrected Verify method behavior for generic methods calls (@Suremaker, #25)
* Split up `Interceptor.Intercept` into a set of 8 strategies, introduce `InterceptionAction`(@FellicePollano, #31)

#### Fixed

* Fix `SetupSequentialContext` to increment counter also after `Throws` (@lukas-ais, #7)
* Make `Mock.Of` work on properties with non-public setters (@yorah, #9, #19)
* Adding (and removing) handlers for events declared on interfaces when `CallBase = true` (@IharBury, #13)
* Distinguish between verification exception and mock crash (@quetzalcoatl, #16)
* Improve thread safety of `Interceptor` class (@FelicePollano, #29)


----

**Note:** Release notes in the above format are not available for ealier versions of Moq. The above
changelog entries have been reconstructed from the Git commit history. What follows below are the
original release notes, for which maintenance stopped around Moq version 4.5. They are nevertheless
included below as they go back further in time.

----


## 4.5

* Updated to .NET 4.5
* Dropped support for .NET < 4.5 and Silverlight
* Remove ILMerge. Depend on Castle NuGet package instead.

## 4.3

* Added support for Roslyn
* Automatically add implemented interfaces to mock

## 4.2

* Improved support for async APIs by making default value a completed task
* Added support for async Returns and Throws
* Improved mock invocation sequence testing
* Improved support for multi-threaded tests
* Added support for named mocks

## 4.1

* Added covariant `IMock<out T>` interface to `Mock<T>`
* Added `It.IsNotNull<T>`
* Fix: 'NullReferenceException when subscribing to an event'
* Added overloads to `Verify` to accept `Times` as a Method Group
* Feature request: `It.IsIn(..)`, `It.IsNotIn(...)`
* Corrected Verify method behavior for generic methods calls
* Differentiate verification error from mock crash
* Fix: Adding (and removing) handlers for events declared on interfaces works when `CallBase = true`.
* Update to latest Castle
* Fix: `Mock.Of` (Functional Syntax) doesn't work on properties with non-public setters
* Fix: Allow to use `CallBase` instead of `Returns`
* Fix: Solved Multi-threading issue - `IndexOutOfRangeException`
* Capability of mocking delegates (event handlers)

## 4.0

* Linq to Mocks: `Mock.Of<T>(x => x.Id == 23 && x.Title == "Rocks!")`
* Fixed issues:
  *  87	`BadImageFormatException` when using a mock with a Visual Studio generated Accessor object
  *  166	Unable to use a delegate to mock a function that takes 5 or more parameters.
  *  168	Call count failure message never says which is the actual invocation count
  *  175	`theMock.Object` failing on VS2010 Beta 1
  *  177	Generic constraint on interface method causes `BadImageFormatException` when getting `Object`.
  *  183	Display what invocations were recieved when the expected one hasn't been met
  *  186	Methods that are not virtual gives non-sense-exception message
  *  188	More `Callback` Overloads
  *  199	Simplify `SetupAllProperties` implementation to simply iterate and call `SetupProperty`
  *  200	Fluent mock does not honor parent mock `CallBase` setting.
  *  202	`Mock.Protected().Expect()` deprecated with no work-around
  *  204	Allow default return values to be specified (per-mock)
  *  205	Error calling `SetupAllProperties` for `Mock<IDataErrorInfo>`
  *  206	Linq-to-Mocks Never Returns on Implicit Boolean Property
  *  207	`NullReferenceException` thrown when using `Mocks.CreateQuery` with implicit boolean expression
  *  208	Can't setup a mock for method that accept lambda expression as argument.
  *  211	`SetupAllProperties` should return the `Mock<T>` instead of `void`. 
  *  223	When a method is defined to make the setup an asserts mock fails
  *  226	Can't raise events on mocked Interop interfaces
  *  229	`CallBase` is not working for virtual events
  *  238	Moq fails to mock events defined in F# 
  *  239	Use `Func` instead of `Predicate`
  *  250	4.0 Beta 2 regression - cannot mock `MethodInfo` when targetting .NET 4
  *  251	When a generic interface also implements a non-generic version, `Verify` does not work in some cases
  *  254	Unable to create mock of `EnvDTE.DTE`
  *  261	Can not use protected setter in public property
  *  267	Generic argument as dependency for method `Setup` overrides all previous method setups for a given method
  *  273	Attempting to create a mock thrown a Type Load exception. The message refers to an inaccessible interface.
  *  276	.Net 3.5 no more supported

## 3.0

* Silverlight support! Finally integrated Jason's Silverlight contribution! Issue #73
* Brand-new simplified event raising syntax (#130): `mock.Raise(foo => foo.MyEvent += null, new MyArgs(...));`
* Support for custom event signatures (not compatible with `EventHandler`): `mock.Raise(foo => foo.MyEvent += null, arg1, arg2, arg3);`
* Substantially improved property setter behavior: `mock.VerifySet(foo => foo.Value = "foo");` (also available for `SetupSet`
* Renamed `Expect*` with `Setup*`
* Vastly simplified custom argument matchers: `public int IsOdd() { return Match<int>.Create(v => i % 2 == 0); }`
* Added support for verifying how many times a member was invoked: `mock.Verify(foo => foo.Do(), Times.Never());`
* Added simple sample app named StoreSample
* Moved Stub functionality to the core API (`SetupProperty` and `SetupAllProperties`)
* Fixed sample ASP.NET MVC app to work with latest version
* Allow custom matchers to be created with a substantially simpler API
* Fixed issue #145 which prevented discrimination of setups by generic method argument types
* Fixed issue #141 which prevented ref arguments matching value types (i.e. a Guid)
* Implemented improvement #131: Add support for `It.IsAny` and custom argument matchers for `SetupSet`/`VerifySet`
* Implemented improvement #124 to render better error messages
* Applied patch from David Kirkland for improvement #125 to improve matching of enumerable parameters
* Implemented improvement #122 to provide custom errors for `Verify`
* Implemented improvement #121 to provide `null` as default value for `Nullable<T>`
* Fixed issue #112 which fixes passing a null argument to a mock constructor
* Implemented improvement #111 to better support params arguments
* Fixed bug #105 about improperly overwriting setups for property getter and setter
* Applied patch from Ihar.Bury for issue #99 related to protected expectations 
* Fixed issue #97 on not being able to use `SetupSet`/`VerifySet` if property did not have a getter
* Better integration with Pex (http://research.microsoft.com/en-us/projects/Pex/)
* Various other minor fixes (#134, #135, #137, #138, #140, etc.)

## 2.6

* Implemented Issue #55: We now provide a `mock.DefaultValue` = [`DefaultValue.Empty` | `DefaultValue.Mock`] which will provide the current behavior (default) or mocks for mockeable return types for loose mock invocations without expectations.
* Added support for stubbing properties from moq-contrib: now you can do `mock.Stub(m => m.Value)` and add stub behavior to the property. `mock.StubAll()` is also provided. This integrates with the `DefaultValue` behavior too, so you can stub entire hierarchies :).
* Added support for mocking methods with `out` and `ref` parameters (Issue #50)
* Applied patch contributed by slava for Issue #72: add support to limit numbor of calls on mocked method (we now have `mock.Expect(...).AtMost(5)`)
* Implemented Issue #94: Easier setter verification: Now we support `ExpectSet(m = m.Value, "foo")` and `VerifySet(m = m.Value, 5)` (Thanks ASP.NET MVC Team!)
* Implemented issue #96: Automatically chain mocks when setting expectations. It's now possible to specify expectations for an entire hierarchy of objects just starting from the root mock. THIS IS REALLY COOL!!!
* Fixed Issue #89: `Expects()` does not always return last expectation
* Implemented Issue 91: Expect a method/property to never be called (added `Never()` method to an expectation. Can be used on methods, property getters and setters)
* Fixed Issue 86: `IsAny<T>` should check if the value is actually of type `T`
* Fixed Issue 88: Cannot mock protected internal virtual methods using `Moq.Protected`
* Fixed Issue 90: Removing event handlers from mocked objects
* Updated demo and added one more test for the dynamic addition of interfaces

## 2.5

* Added support for mocking protected members
* Added new way of extending argument matchers which is now very straightforward
* Added support for mocking events
* Added support for firing events from expectations
* Removed usage of MBROs which caused inconsistencies in mocking features
* Added `ExpectGet` and `ExpectSet` to better support properties, and provide better intellisense.
* Added verification with expressions, which better supports Arrange-Act-Assert testing model (can do `Verify(m => m.Do(...)))`
* Added `Throws<TException>`
* Added `mock.CallBase` property to specify whether the virtual members base implementation should be called
* Added support for implementing and setting expectations and verifying additional interfaces in the mock, via the new `mock.As<TInterface>()` method (thanks Fernando Simonazzi!)
* Improved argument type matching for `Is`/`IsAny` (thanks Jeremy.Skinner!)

## 2.0

* Refactored fluent API on mocks. This may cause some existing tests to fail, but the fix is trivial (just reorder the calls to `Callback`, `Returns` and `Verifiable`)
* Added support for retrieving a `Mock<T>` from a `T` instance created by a mock.
* Added support for retrieving the invocation arguments from a `Callback` or `Returns`.
* Implemented `AtMostOnce()` constraint 
* Added support for creating MBROs with protected constructors
* Loose mocks now return default empty arrays and `IEnumerables` instead of `null`s

## 1.5.1

* Refactored `MockFactory` to make it simpler and more explicit to use with regards to verification. Thanks Garry Shutler for the feedback! 

## 1.5

* Added `MockFactory` to allow easy construction of multiple mocks with the same behavior and verification 

## 1.4

* Added support for passing constructor arguments for mocked classes.
* Improved code documentation 

## 1.3

 * Added support for overriding expectations set previously on a Mock. Now adding a second expectation for the same method/property call will override the existing one. This facilitates setting up default expectations in a fixture setup and overriding when necessary in a specific test.
 * Added support for mock verification. Both `Verify` and `VerifyAll` are provided for more flexibility (the former only verifies methods marked `Verifiable`) 

## 1.2

* Added support for `MockBehavior` mock constructor argument to affect the way the mocks expect or throw on calls. 

## 1.1

* Merged branch for dynamic types. Now Moq is based on Castle DynamicProxy2 to support a wider range of mock targets.
* Added ILMerge so that Castle libraries are merged into Moq assembly (no need for external references and avoid conflicts)

## 1.0

* Initial release, initial documentation process in place, etc.
