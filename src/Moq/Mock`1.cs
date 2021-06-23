// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD, and Contributors.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading;

using Moq.Language;
using Moq.Language.Flow;
using Moq.Properties;

namespace Moq
{
	/// <summary>
	///   Provides a mock implementation of <typeparamref name="T"/>.
	/// </summary>
	/// <typeparam name="T">Type to mock, which can be an interface, a class, or a delegate.</typeparam>
	/// <remarks>
	///   Any interface type can be used for mocking, but for classes, only abstract and virtual members can be mocked.
	///   <para>
	///     The behavior of the mock with regards to the setups and the actual calls is determined by the optional
	///     <see cref = "MockBehavior" /> that can be passed to the<see cref="Mock{T}(MockBehavior)"/> constructor.
	///   </para>
	/// </remarks>
	/// <example group="overview">
	///   The following example shows establishing setups with specific values for method invocations:
	///   <code>
	///     // Arrange
	///     var order = new Order(TALISKER, 50);
	///     var warehouse = new Mock&lt;IWarehouse&gt;();
	///     warehouse.Setup(w => w.HasInventory(TALISKER, 50)).Returns(true);
	///
	///     // Act
	///     order.Fill(warehouse.Object);
	///
	///     // Assert
	///     Assert.True(order.IsFilled);
	///   </code>
	/// </example>
	/// <example group="overview">
	///   The following example shows how to use the <see cref="It"/> class
	///   to specify conditions for arguments instead of specific values:
	///   <code>
	///     // Arrange
	///     var order = new Order(TALISKER, 50);
	///     var warehouse = new Mock&lt;IWarehouse&gt;();
	///
	///     // shows how to expect a value within a range:
	///     warehouse.Setup(x => x.HasInventory(
	///                              It.IsAny&lt;string&gt;(),
	///                              It.IsInRange(0, 100, Range.Inclusive)))
	///              .Returns(false);
	///
	///     // shows how to throw for unexpected calls.
	///     warehouse.Setup(x => x.Remove(
	///                              It.IsAny&lt;string&gt;(),
	///                              It.IsAny&lt;int&gt;()))
	///              .Throws(new InvalidOperationException());
	///
	///     // Act
	///     order.Fill(warehouse.Object);
	///
	///     // Assert
	///     Assert.False(order.IsFilled);
	///   </code>
	/// </example>
	public partial class Mock<T> : Mock, IMock<T> where T : class
	{
		private static Type[] inheritedInterfaces;
		private static int serialNumberCounter;

		static Mock()
		{
			inheritedInterfaces =
				typeof(T)
				.GetInterfaces()
				.Where(i => ProxyFactory.Instance.IsTypeVisible(i) && !i.IsImport)
				.ToArray();

			serialNumberCounter = 0;
		}

		private T instance;
		private List<Type> additionalInterfaces;
		private Dictionary<Type, object> configuredDefaultValues;
		private object[] constructorArguments;
		private DefaultValueProvider defaultValueProvider;
		private EventHandlerCollection eventHandlers;
		private InvocationCollection invocations;
		private string name;
		private SetupCollection setups;

		private MockBehavior behavior;
		private bool callBase;
		private Switches switches;

#region Ctors

		/// <summary>
		/// Ctor invoked by AsTInterface exclusively.
		/// </summary>
		internal Mock(bool skipInitialize)
		{
			// HACK: this is quick hackish. 
			// In order to avoid having an IMock<T> I relevant members 
			// virtual so that As<TInterface> overrides them (i.e. Interceptor).
			// The skipInitialize parameter is not used at all, and it's 
			// just to differentiate this ctor that should do nothing 
			// from the regular ones which initializes the proxy, etc.
		}

		/// <summary>
		///   Initializes an instance of the mock with <see cref="MockBehavior.Default"/> behavior.
		/// </summary>
		/// <example>
		///   <code>
		///     var mock = new Mock&lt;IFormatProvider&gt;();
		///   </code>
		/// </example>
		public Mock()
			: this(MockBehavior.Default)
		{
		}

		/// <summary>
		///   Initializes an instance of the mock with <see cref="MockBehavior.Default"/> behavior
		///   and with the given constructor arguments for the class. (Only valid when <typeparamref name="T"/> is a class.)
		/// </summary>
		/// <param name="args">Optional constructor arguments if the mocked type is a class.</param>
		/// <remarks>
		///   The mock will try to find the best match constructor given the constructor arguments,
		///   and invoke that to initialize the instance.This applies only for classes, not interfaces.
		/// </remarks>
		/// <example>
		///   <code>
		///     var mock = new Mock&lt;MyProvider&gt;(someArgument, 25);
		///   </code>
		/// </example>
		public Mock(params object[] args)
			: this(MockBehavior.Default, args)
		{
		}

		/// <summary>
		///   Initializes an instance of the mock with the specified <see cref="MockBehavior"/> behavior.
		/// </summary>
		/// <param name="behavior">Behavior of the mock.</param>
		/// <example>
		///   <code>
		///     var mock = new Mock&lt;IFormatProvider&gt;(MockBehavior.Strict);
		///   </code>
		/// </example>
		public Mock(MockBehavior behavior)
			: this(behavior, new object[0])
		{
		}

		/// <summary>
		///   Initializes an instance of the mock with a specific <see cref="MockBehavior"/> behavior
		///   and with the given constructor arguments for the class.
		/// </summary>
		/// <param name="behavior">Behavior of the mock.</param>
		/// <param name="args">Optional constructor arguments if the mocked type is a class.</param>
		/// <remarks>
		///   The mock will try to find the best match constructor given the constructor arguments,
		///   and invoke that to initialize the instance. This applies only to classes, not interfaces.
		/// </remarks>
		public Mock(MockBehavior behavior, params object[] args)
		{
			Guard.IsMockable(typeof(T));

			if (args == null)
			{
				args = new object[] { null };
			}

			this.additionalInterfaces = new List<Type>();
			this.behavior = behavior;
			this.configuredDefaultValues = new Dictionary<Type, object>();
			this.constructorArguments = args;
			this.defaultValueProvider = DefaultValueProvider.Empty;
			this.eventHandlers = new EventHandlerCollection();
			this.invocations = new InvocationCollection(this);
			this.name = CreateUniqueDefaultMockName();
			this.setups = new SetupCollection();
			this.switches = Switches.Default;

			this.CheckParameters();
		}

		/// <summary>
		///   Initializes an instance of the mock using the given constructor call including its
		///   argument values and with a specific <see cref="MockBehavior"/> behavior.
		/// </summary>
		/// <param name="newExpression">Lambda expression that creates an instance of <typeparamref name="T"/>.</param>
		/// <param name="behavior">Behavior of the mock.</param>
		/// <example>
		/// <code>var mock = new Mock&lt;MyProvider&gt;(() => new MyProvider(someArgument, 25), MockBehavior.Loose);</code>
		/// </example>
		public Mock(Expression<Func<T>> newExpression, MockBehavior behavior = MockBehavior.Default)
			: this(behavior, Expressions.Visitors.ConstructorCallVisitor.ExtractArgumentValues(newExpression))
		{
		}

		private static string CreateUniqueDefaultMockName()
		{
			var serialNumber = Interlocked.Increment(ref serialNumberCounter);

			var name = new StringBuilder();
			name.Append("Mock<").AppendNameOf(typeof(T)).Append(':').Append(serialNumber).Append('>');
			return name.ToString();
		}

		private void CheckParameters()
		{
			if (this.constructorArguments.Length > 0)
			{
				if (typeof(T).IsInterface)
				{
					throw new ArgumentException(Resources.ConstructorArgsForInterface);
				}
				if (typeof(T).IsDelegateType())
				{
					throw new ArgumentException(Resources.ConstructorArgsForDelegate);
				}
			}
		}

#endregion

#region Properties

		/// <inheritdoc/>
		public override MockBehavior Behavior => this.behavior;

		/// <inheritdoc/>
		public override bool CallBase
		{
			get => this.callBase;
			set
			{
				if (value && this.MockedType.IsDelegateType())
				{
					throw new NotSupportedException(Resources.CallBaseCannotBeUsedWithDelegateMocks);
				}

				this.callBase = value;
			}
		}

		internal override object[] ConstructorArguments => this.constructorArguments;

		internal override Dictionary<Type, object> ConfiguredDefaultValues => this.configuredDefaultValues;

		/// <summary>
		/// Gets or sets the <see cref="DefaultValueProvider"/> instance that will be used
		/// e. g. to produce default return values for unexpected invocations.
		/// </summary>
		public override DefaultValueProvider DefaultValueProvider
		{
			get => this.defaultValueProvider;
			set => this.defaultValueProvider = value ?? throw new ArgumentNullException(nameof(value));
		}

		internal override DefaultValueProvider AutoSetupPropertiesDefaultValueProvider { get; set; }

		internal override EventHandlerCollection EventHandlers => this.eventHandlers;

		internal override List<Type> AdditionalInterfaces => this.additionalInterfaces;

		internal override InvocationCollection MutableInvocations => this.invocations;

		internal override bool IsObjectInitialized => this.instance != null;

		/// <summary>
		///   Exposes the mocked object instance.
		/// </summary>
		public virtual new T Object
		{
			get { return (T)base.Object; }
		}

		/// <summary>
		///   Allows naming of your mocks, so they can be easily identified in error messages (e.g. from failed assertions).
		/// </summary>
		public string Name
		{
			get => this.name;
			set => this.name = value;
		}

		/// <summary>
		///   Returns the name of the mock.
		/// </summary>
		public override string ToString()
		{
			return this.Name;
		}

		private void InitializeInstance()
		{
			// Determine the set of interfaces that the proxy object should additionally implement.
			var additionalInterfaceCount = this.AdditionalInterfaces.Count;
			var interfaces = new Type[1 + additionalInterfaceCount];
			interfaces[0] = typeof(IMocked<T>);
			this.AdditionalInterfaces.CopyTo(0, interfaces, 1, additionalInterfaceCount);

			this.instance = (T)ProxyFactory.Instance.CreateProxy(
				typeof(T),
				this,
				interfaces,
				this.constructorArguments);
		}

		/// <summary>
		/// Returns the mocked object value.
		/// </summary>
		protected override object OnGetObject()
		{
			if (this.instance == null)
			{
				this.InitializeInstance();
			}

			return this.instance;
		}

		internal override Type MockedType => typeof(T);

		internal override SetupCollection MutableSetups => this.setups;

		internal override Type[] InheritedInterfaces => Mock<T>.inheritedInterfaces;

		/// <summary>
		/// A set of switches that influence how this mock will operate.
		/// You can opt in or out of certain features via this property.
		/// </summary>
		public override Switches Switches
		{
			get => this.switches;
			set => this.switches = value;
		}

#endregion

		/// <summary>
		///   Adds an interface implementation to the mock, allowing setups to be specified for it.
		/// </summary>
		/// <remarks>
		///   This method can only be called before the first use of the mock <see cref="Object"/> property,
		///   at which point the runtime type has already been generated and no more interfaces can be added to it.
		///   <para>
		///     Also, <typeparamref name="TInterface"/> must be an interface and not a class,
		///     which must be specified when creating the mock instead.
		///   </para>
		/// </remarks>
		/// <typeparam name="TInterface">Type of interface to cast the mock to.</typeparam>
		/// <exception cref="ArgumentException">The <typeparamref name="TInterface"/> specified is not an interface.</exception>
		/// <exception cref="InvalidOperationException">
		///   The mock type has already been generated by accessing the <see cref="Object"/> property.
		/// </exception>
		/// <example>
		///   The following example creates a mock for the main interface
		///   and later adds <see cref="IDisposable"/> to it to verify it's called by the consumer code:
		///   <code>
		///     var mock = new Mock&lt;IProcessor&gt;();
		///     mock.Setup(x =&gt; x.Execute("ping"));
		///
		///     // add IDisposable interface
		///     var disposable = mock.As&lt;IDisposable&gt;();
		///     disposable.Setup(d => d.Dispose())
		///               .Verifiable();
		///   </code>
		/// </example>
		public override Mock<TInterface> As<TInterface>()
		{
			var interfaceType = typeof(TInterface);

			if (!interfaceType.IsInterface)
			{
				throw new ArgumentException(Resources.AsMustBeInterface);
			}

			if (typeof(TInterface) == typeof(T))
			{
				return (Mock<TInterface>)(Mock)this;
			}

			if (this.IsObjectInitialized && this.ImplementsInterface(interfaceType) == false)
			{
				throw new InvalidOperationException(Resources.AlreadyInitialized);
			}

			if (this.AdditionalInterfaces.Contains(interfaceType) == false)
			{
				// We get here for either of two reasons:
				//
				// 1. We are being asked to implement an interface that the mocked type does *not* itself
				//    inherit or implement. We need to hand this interface type to DynamicProxy's
				//    `CreateClassProxy` method as an additional interface to be implemented.
				//
				// 2. The user is possibly going to create a setup through an interface type that the
				//    mocked type *does* implement. Since the mocked type might implement that interface's
				//    methods non-virtually, we can only intercept those if DynamicProxy reimplements the
				//    interface in the generated proxy type. Therefore we do the same as for (1).
				this.AdditionalInterfaces.Add(interfaceType);
			}

			return new AsInterface<TInterface>(this);
		}

#region Setup

		/// <summary>
		///   Specifies a setup on the mocked type for a call to a <see langword="void"/> method.
		/// </summary>
		/// <param name="expression">Lambda expression that specifies the expected method invocation.</param>
		/// <remarks>
		///   If more than one setup is specified for the same method or property,
		///   the latest one wins and is the one that will be executed.
		/// </remarks>
		/// <example group="setups">
		///   <code>
		///     var mock = new Mock&lt;IProcessor&gt;();
		///     mock.Setup(x => x.Execute("ping"));
		///   </code>
		/// </example>
		public ISetup<T> Setup(Expression<Action<T>> expression)
		{
			var setup = Mock.Setup(this, expression, null);
			return new VoidSetupPhrase<T>(setup);
		}

		/// <summary>
		///   Specifies a setup on the mocked type for a call to a non-<see langword="void"/> (value-returning) method.
		/// </summary>
		/// <param name="expression">Lambda expression that specifies the method invocation.</param>
		/// <typeparam name="TResult">Type of the return value. Typically omitted as it can be inferred from the expression.</typeparam>
		/// <remarks>
		///   If more than one setup is specified for the same method or property,
		///   the latest one wins and is the one that will be executed.
		/// </remarks>
		/// <example group="setups">
		///   <code>
		///     mock.Setup(x => x.HasInventory("Talisker", 50))
		///         .Returns(true);
		///   </code>
		/// </example>
		public ISetup<T, TResult> Setup<TResult>(Expression<Func<T, TResult>> expression)
		{
			var setup = Mock.Setup(this, expression, null);
			return new NonVoidSetupPhrase<T, TResult>(setup);
		}

		/// <summary>
		///   Specifies a setup on the mocked type for a call to a property getter.
		/// </summary>
		/// <param name="expression">Lambda expression that specifies the property getter.</param>
		/// <typeparam name="TProperty">Type of the property. Typically omitted as it can be inferred from the expression.</typeparam>
		/// <remarks>
		///   If more than one setup is set for the same property getter,
		///   the latest one wins and is the one that will be executed.
		/// </remarks>
		/// <example group="setups">
		///   <code>
		///     mock.SetupGet(x => x.Suspended)
		///         .Returns(true);
		///   </code>
		/// </example>
		public ISetupGetter<T, TProperty> SetupGet<TProperty>(Expression<Func<T, TProperty>> expression)
		{
			var setup = Mock.SetupGet(this, expression, null);
			return new NonVoidSetupPhrase<T, TProperty>(setup);
		}

		/// <summary>
		///   Specifies a setup on the mocked type for a call to a property setter.
		/// </summary>
		/// <param name="setterExpression">The Lambda expression that sets a property to a value.</param>
		/// <typeparam name="TProperty">Type of the property.</typeparam>
		/// <remarks>
		///   If more than one setup is set for the same property setter,
		///   the latest one wins and is the one that will be executed.
		///   <para>
		///     This overloads allows the use of a callback already typed for the property type.
		///   </para>
		/// </remarks>
		/// <example group="setups">
		///   <code>
		///     mock.SetupSet(x => x.Suspended = true);
		///   </code>
		/// </example>
		public ISetupSetter<T, TProperty> SetupSet<TProperty>(Action<T> setterExpression)
		{
			Guard.NotNull(setterExpression, nameof(setterExpression));
			var expression = ExpressionReconstructor.Instance.ReconstructExpression(setterExpression, this.ConstructorArguments);

			var setup = Mock.SetupSet(this, expression, condition: null);
			return new SetterSetupPhrase<T, TProperty>(setup);
		}

		/// <summary>
		///   Specifies a setup on the mocked type for a call to a property setter.
		/// </summary>
		/// <param name="setterExpression">Lambda expression that sets a property to a value.</param>
		/// <remarks>
		///   If more than one setup is set for the same property setter,
		///   the latest one wins and is the one that will be executed.
		/// </remarks>
		/// <example group="setups">
		///   <code>
		///     mock.SetupSet(x => x.Suspended = true);
		///   </code>
		/// </example>
		public ISetup<T> SetupSet(Action<T> setterExpression)
		{
			Guard.NotNull(setterExpression, nameof(setterExpression));
			var expression = ExpressionReconstructor.Instance.ReconstructExpression(setterExpression, this.ConstructorArguments);

			var setup = Mock.SetupSet(this, expression, condition: null);
			return new VoidSetupPhrase<T>(setup);
		}

		/// <summary>
		///   Specifies a setup on the mocked type for a call to an event add.
		/// </summary>
		/// <param name="addExpression">Lambda expression that adds an event.</param>
		/// <remarks>
		///   If more than one setup is set for the same event add,
		///   the latest one wins and is the one that will be executed.
		/// </remarks>
		/// <example group="setups">
		///   <code>
		///     mock.SetupAdd(x => x.EventHandler += (s, e) => {});
		///   </code>
		/// </example>
		public ISetup<T> SetupAdd(Action<T> addExpression)
		{
			Guard.NotNull(addExpression, nameof(addExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(addExpression, this.ConstructorArguments);

			var setup = Mock.SetupAdd(this, expression, condition: null);
			return new VoidSetupPhrase<T>(setup);
		}

		/// <summary>
		///   Specifies a setup on the mocked type for a call to an event remove.
		/// </summary>
		/// <param name="removeExpression">Lambda expression that removes an event.</param>
		/// <remarks>
		///   If more than one setup is set for the same event remove,
		///   the latest one wins and is the one that will be executed.
		/// </remarks>
		/// <example group="setups">
		///   <code>
		///     mock.SetupRemove(x => x.EventHandler -= (s, e) => {});
		///   </code>
		/// </example>
		public ISetup<T> SetupRemove(Action<T> removeExpression)
		{
			Guard.NotNull(removeExpression, nameof(removeExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(removeExpression, this.ConstructorArguments);

			var setup = Mock.SetupRemove(this, expression, condition: null);
			return new VoidSetupPhrase<T>(setup);
		}

		/// <summary>
		///   Specifies that the given property should have "property behavior",
		///   meaning that setting its value will cause it to be saved and later returned when the property is requested.
		///   (This is also known as "stubbing".)
		/// </summary>
		/// <param name="property">Property expression to stub.</param>
		/// <typeparam name="TProperty">
		///   Type of the property, inferred from the property expression (does not need to be specified).
		/// </typeparam>
		/// <example group="setups">
		///   If you have an interface with an int property <c>Value</c>,
		///   you might stub it using the following straightforward call:
		///   <code>
		///     var mock = new Mock&lt;IHaveValue&gt;();
		///     mock.SetupProperty(v => v.Value);
		///   </code>
		///   After the <c>SetupProperty</c> call has been issued, setting and retrieving
		///   the object value will behave as expected:
		///   <code>
		///     IHaveValue v = mock.Object;
		///     v.Value = 5;
		///     Assert.Equal(5, v.Value);
		///   </code>
		/// </example>
		public Mock<T> SetupProperty<TProperty>(Expression<Func<T, TProperty>> property)
		{
			return this.SetupProperty(property, default(TProperty));
		}

		/// <summary>
		///   Specifies that the given property should have "property behavior",
		///   meaning that setting its value will cause it to be saved and later returned when the property is requested.
		///   This overload allows setting the initial value for the property.
		///   (This is also known as "stubbing".)
		/// </summary>
		/// <param name="property">Property expression to stub.</param>
		/// <param name="initialValue">Initial value for the property.</param>
		/// <typeparam name="TProperty">
		///   Type of the property, inferred from the property expression (does not need to be specified).
		/// </typeparam>
		/// <example group="setups">
		///   If you have an interface with an int property <c>Value</c>,
		///   you might stub it using the following straightforward call:
		///   <code>
		///     var mock = new Mock&lt;IHaveValue&gt;();
		///     mock.SetupProperty(v => v.Value, 5);
		///   </code>
		///   After the <c>SetupProperty</c> call has been issued, setting and retrieving the object value
		///   will behave as expected:
		///   <code>
		///     IHaveValue v = mock.Object;
		///     Assert.Equal(5, v.Value); // Initial value was stored
		///
		///     // New value set which changes the initial value
		///     v.Value = 6;
		///     Assert.Equal(6, v.Value);
		///   </code>
		/// </example>
		public Mock<T> SetupProperty<TProperty>(Expression<Func<T, TProperty>> property, TProperty initialValue)
		{
			Guard.NotNull(property, nameof(property));

			var pi = property.ToPropertyInfo();
			Guard.CanRead(pi);
			Guard.CanWrite(pi);

			TProperty value = initialValue;
			this.SetupGet(property).Returns(() => value);
			Mock.SetupSet(this, property.AssignItIsAny(), condition: null).SetCallbackBehavior(new Action<TProperty>(p => value = p));
			return this;
		}

		/// <summary>
		///   Specifies that the all properties on the mock should have "property behavior",
		///   meaning that setting their value will cause them to be saved and later returned when the properties is requested.
		///   (This is also known as "stubbing".)
		///   The default value for each property will be the one generated as specified by the <see cref="Mock.DefaultValue"/>
		///   property for the mock.
		/// </summary>
		/// <remarks>
		///   If the mock's <see cref="Mock.DefaultValue"/> is set to <see cref="DefaultValue.Mock"/>,
		///   the mocked default values will also get all properties setup recursively.
		/// </remarks>
		public Mock<T> SetupAllProperties()
		{
			SetupAllProperties(this);
			return this;
		}

		/// <summary>
		/// Return a sequence of values, once per call.
		/// </summary>
		public ISetupSequentialResult<TResult> SetupSequence<TResult>(Expression<Func<T, TResult>> expression)
		{
			var setup = Mock.SetupSequence(this, expression);
			return new SetupSequencePhrase<TResult>(setup);
		}

		/// <summary>
		/// Performs a sequence of actions, one per call.
		/// </summary>
		public ISetupSequentialAction SetupSequence(Expression<Action<T>> expression)
		{
			var setup = Mock.SetupSequence(this, expression);
			return new SetupSequencePhrase(setup);
		}

#endregion

#region When

		/// <summary>
		///   Allows setting up a conditional setup.
		///   Conditional setups are only matched by an invocation
		///   when the specified condition evaluates to <see langword="true"/>
		///   at the time when the invocation occurs.
		/// </summary>
		/// <param name="condition">
		///   The condition that should be checked
		///   when a setup is being matched against an invocation.
		/// </param>
		public ISetupConditionResult<T> When(Func<bool> condition)
		{
			return new WhenPhrase<T>(this, new Condition(condition));
		}

#endregion

#region Verify

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock.
		///   Use in conjunction with the default <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		/// <example group="verification">
		///   This example assumes that the mock has been used, and later we want to verify
		///   that a given invocation with specific parameters was performed:
		///   <code>
		///     var mock = new Mock&lt;IProcessor&gt;();
		///
		///     ... // exercise mock
		///
		///     // Will throw if the test code didn't call Execute with a "ping" string argument.
		///     mock.Verify(proc => proc.Execute("ping"));
		///   </code>
		/// </example>
		public void Verify(Expression<Action<T>> expression)
		{
			Mock.Verify(this, expression, Times.AtLeastOnce(), null);
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock.
		///   Use in conjunction with the default <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void Verify(Expression<Action<T>> expression, Times times)
		{
			Mock.Verify(this, expression, times, null);
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock.
		///   Use in conjunction with the default <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void Verify(Expression<Action<T>> expression, Func<Times> times)
		{
			Verify(expression, times());
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock,
		///   specifying a failure error message.
		///   Use in conjunction with the default <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		public void Verify(Expression<Action<T>> expression, string failMessage)
		{
			Mock.Verify(this, expression, Times.AtLeastOnce(), failMessage);
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock,
		///   specifying a failure error message.
		///   Use in conjunction with the default <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void Verify(Expression<Action<T>> expression, Times times, string failMessage)
		{
			Mock.Verify(this, expression, times, failMessage);
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock,
		///   specifying a failure error message.
		///   Use in conjunction with the default <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void Verify(Expression<Action<T>> expression, Func<Times> times, string failMessage)
		{
			Mock.Verify(this, expression, times(), failMessage);
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock.
		///   Use in conjunction with the default <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <typeparam name="TResult">Type of return value from the expression.</typeparam>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		/// <example group="verification">
		///   This example assumes that the mock has been used, and later we want to verify
		///   that a given invocation with specific parameters was performed:
		///   <code>
		///     var mock = new Mock&lt;IWarehouse&gt;();
		///
		///     ... // exercise mock
		///
		///     // Will throw if the test code didn't call HasInventory.
		///     mock.Verify(warehouse => warehouse.HasInventory(TALISKER, 50));
		///   </code>
		/// </example>
		public void Verify<TResult>(Expression<Func<T, TResult>> expression)
		{
			Mock.Verify(this, expression, Times.AtLeastOnce(), null);
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock.
		///   Use in conjunction with the default <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <typeparam name="TResult">Type of return value from the expression.</typeparam>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void Verify<TResult>(Expression<Func<T, TResult>> expression, Times times)
		{
			Mock.Verify(this, expression, times, null);
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock.
		///   Use in conjunction with the default <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <typeparam name="TResult">Type of return value from the expression.</typeparam>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void Verify<TResult>(Expression<Func<T, TResult>> expression, Func<Times> times)
		{
			Mock.Verify(this, expression, times(), null);
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock,
		///   specifying a failure error message.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <typeparam name="TResult">Type of return value from the expression.</typeparam>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		/// <example group="verification">
		///   This example assumes that the mock has been used, and later we want to verify
		///   that a given invocation with specific parameters was performed:
		///   <code>
		///     var mock = new Mock&lt;IWarehouse&gt;();
		///
		///     ... // exercise mock
		///
		///     // Will throw if the test code didn't call HasInventory.
		///     mock.Verify(warehouse => warehouse.HasInventory(TALISKER, 50),
		///                 "When filling orders, inventory has to be checked");
		///   </code>
		/// </example>
		public void Verify<TResult>(Expression<Func<T, TResult>> expression, string failMessage)
		{
			Mock.Verify(this, expression, Times.AtLeastOnce(), failMessage);
		}

		/// <summary>
		///   Verifies that a specific invocation matching the given expression was performed on the mock,
		///   specifying a failure error message.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <typeparam name="TResult">Type of return value from the expression.</typeparam>
		/// <exception cref="MockException">
		///   The invocation was not called the number times specified by <paramref name="times"/>.
		/// </exception>
		public void Verify<TResult>(Expression<Func<T, TResult>> expression, Times times, string failMessage)
		{
			Mock.Verify(this, expression, times, failMessage);
		}

		/// <summary>
		///   Verifies that a property was read on the mock.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <typeparam name="TProperty">
		///   Type of the property to verify. Typically omitted as it can be inferred from the expression's return type.
		/// </typeparam>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		/// <example group="verification">
		///   This example assumes that the mock has been used, and later we want to verify
		///   that a given property was retrieved from it:
		///   <code>
		///     var mock = new Mock&lt;IWarehouse&gt;();
		///
		///     ... // exercise mock
		///
		///     // Will throw if the test code didn't retrieve the IsClosed property.
		///     mock.VerifyGet(warehouse => warehouse.IsClosed);
		///   </code>
		/// </example>
		public void VerifyGet<TProperty>(Expression<Func<T, TProperty>> expression)
		{
			Mock.VerifyGet(this, expression, Times.AtLeastOnce(), null);
		}

		/// <summary>
		///   Verifies that a property was read on the mock.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="expression">Expression to verify.</param>
		/// <typeparam name="TProperty">
		///   Type of the property to verify. Typically omitted as it can be inferred from the expression's return type.
		/// </typeparam>
		/// <exception cref="MockException">
		///   The invocation was not called the number times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyGet<TProperty>(Expression<Func<T, TProperty>> expression, Times times)
		{
			Mock.VerifyGet(this, expression, times, null);
		}

		/// <summary>
		///   Verifies that a property was read on the mock.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="expression">Expression to verify.</param>
		/// <typeparam name="TProperty">
		///   Type of the property to verify. Typically omitted as it can be inferred from the expression's return type.
		/// </typeparam>
		/// <exception cref="MockException">
		///   The invocation was not called the number times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyGet<TProperty>(Expression<Func<T, TProperty>> expression, Func<Times> times)
		{
			VerifyGet(this, expression, times(), null);
		}

		/// <summary>
		///   Verifies that a property was read on the mock, specifying a failure error message.
		/// </summary>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <typeparam name="TProperty">
		///   Type of the property to verify. Typically omitted as it can be inferred from the expression's return type.
		/// </typeparam>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		public void VerifyGet<TProperty>(Expression<Func<T, TProperty>> expression, string failMessage)
		{
			Mock.VerifyGet(this, expression, Times.AtLeastOnce(), failMessage);
		}

		/// <summary>
		///   Verifies that a property was read on the mock, specifying a failure error message.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <typeparam name="TProperty">
		///   Type of the property to verify. Typically omitted as it can be inferred from the expression's return type.
		/// </typeparam>
		/// <exception cref="MockException">
		///   The invocation was not called the number times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyGet<TProperty>(Expression<Func<T, TProperty>> expression, Times times, string failMessage)
		{
			Mock.VerifyGet(this, expression, times, failMessage);
		}

		/// <summary>
		///   Verifies that a property was read on the mock, specifying a failure error message.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="expression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <typeparam name="TProperty">
		///   Type of the property to verify. Typically omitted as it can be inferred from the expression's return type.
		/// </typeparam>
		/// <exception cref="MockException">
		///   The invocation was not called the number times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyGet<TProperty>(Expression<Func<T, TProperty>> expression, Func<Times> times, string failMessage)
		{
			VerifyGet(this, expression, times(), failMessage);
		}

		/// <summary>
		///   Verifies that a property was set on the mock.
		/// </summary>
		/// <param name="setterExpression">Expression to verify.</param>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		/// <example group="verification">
		///   This example assumes that the mock has been used, and later we want to verify
		///   that a given property was set on it:
		///   <code>
		///     var mock = new Mock&lt;IWarehouse&gt;();
		///
		///     ... // exercise mock
		///
		///     // Will throw if the test code didn't set the IsClosed property.
		///     mock.VerifySet(warehouse => warehouse.IsClosed = true);
		///   </code>
		/// </example>
		public void VerifySet(Action<T> setterExpression)
		{
			Guard.NotNull(setterExpression, nameof(setterExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(setterExpression, this.ConstructorArguments);
			Mock.VerifySet(this, expression, Times.AtLeastOnce(), null);
		}

		/// <summary>
		///   Verifies that a property was set on the mock.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="setterExpression">Expression to verify.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifySet(Action<T> setterExpression, Times times)
		{
			Guard.NotNull(setterExpression, nameof(setterExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(setterExpression, this.ConstructorArguments);
			Mock.VerifySet(this, expression, times, null);
		}

		/// <summary>
		///   Verifies that a property was set on the mock.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="setterExpression">Expression to verify.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifySet(Action<T> setterExpression, Func<Times> times)
		{
			Guard.NotNull(setterExpression, nameof(setterExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(setterExpression, this.ConstructorArguments);
			Mock.VerifySet(this, expression, times(), null);
		}

		/// <summary>
		///   Verifies that a property was set on the mock, specifying a failure message.
		/// </summary>
		/// <param name="setterExpression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		/// <example>
		///   This example assumes that the mock has been used, and later we want to verify
		///   that a given property was set on it:
		///   <code>
		///     var mock = new Mock&lt;IWarehouse&gt;();
		///
		///     ... // exercise mock
		///
		///     // Will throw if the test code didn't set the IsClosed property.
		///     mock.VerifySet(warehouse =&gt; warehouse.IsClosed = true,
		///                    "Warehouse should always be closed after the action");
		///   </code>
		/// </example>
		public void VerifySet(Action<T> setterExpression, string failMessage)
		{
			Guard.NotNull(setterExpression, nameof(setterExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(setterExpression, this.ConstructorArguments);
			Mock.VerifySet(this, expression, Times.AtLeastOnce(), failMessage);
		}

		/// <summary>
		///   Verifies that a property was set on the mock, specifying a failure message.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="setterExpression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifySet(Action<T> setterExpression, Times times, string failMessage)
		{
			Guard.NotNull(setterExpression, nameof(setterExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(setterExpression, this.ConstructorArguments);
			Mock.VerifySet(this, expression, times, failMessage);
		}

		/// <summary>
		///   Verifies that a property was set on the mock, specifying a failure message.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="setterExpression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifySet(Action<T> setterExpression, Func<Times> times, string failMessage)
		{
			Guard.NotNull(setterExpression, nameof(setterExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(setterExpression, this.ConstructorArguments);
			Mock.VerifySet(this, expression , times(), failMessage);
		}

		/// <summary>
		///   Verifies that an event was added to the mock.
		/// </summary>
		/// <param name="addExpression">Expression to verify.</param>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		/// <example group="verification">
		///   This example assumes that the mock has been used, and later we want to verify
		///   that a given event handler was subscribed to an event:
		///   <code>
		///     var mock = new Mock&lt;IWarehouse&gt;();
		///
		///     ... // exercise mock
		///
		///     // Will throw if the test code didn't subscribe to the OnClosed event.
		///     mock.VerifyAdd(warehouse => warehouse.OnClosed += It.IsAny&lt;EventHandler&gt;());
		///   </code>
		/// </example>
		public void VerifyAdd(Action<T> addExpression)
		{
			Guard.NotNull(addExpression, nameof(addExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(addExpression, this.ConstructorArguments);
			Mock.VerifyAdd(this, expression, Times.AtLeastOnce(), null);
		}

		/// <summary>
		///   Verifies that an event was added to the mock.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="addExpression">Expression to verify.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyAdd(Action<T> addExpression, Times times)
		{
			Guard.NotNull(addExpression, nameof(addExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(addExpression, this.ConstructorArguments);
			Mock.VerifyAdd(this, expression, times, null);
		}

		/// <summary>
		///   Verifies that an event was added to the mock.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="addExpression">Expression to verify.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyAdd(Action<T> addExpression, Func<Times> times)
		{
			Guard.NotNull(addExpression, nameof(addExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(addExpression, this.ConstructorArguments);
			Mock.VerifyAdd(this, expression, times(), null);
		}

		/// <summary>
		///   Verifies that an event was added to the mock, specifying a failure message.
		/// </summary>
		/// <param name="addExpression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		public void VerifyAdd(Action<T> addExpression, string failMessage)
		{
			Guard.NotNull(addExpression, nameof(addExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(addExpression, this.ConstructorArguments);
			Mock.VerifyAdd(this, expression, Times.AtLeastOnce(), failMessage);
		}

		/// <summary>
		///   Verifies that an event was added to the mock, specifying a failure message.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="addExpression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyAdd(Action<T> addExpression, Times times, string failMessage)
		{
			Guard.NotNull(addExpression, nameof(addExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(addExpression, this.ConstructorArguments);
			Mock.VerifyAdd(this, expression, times, failMessage);
		}

		/// <summary>
		///   Verifies that an event was added to the mock, specifying a failure message.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="addExpression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyAdd(Action<T> addExpression, Func<Times> times, string failMessage)
		{
			Guard.NotNull(addExpression, nameof(addExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(addExpression, this.ConstructorArguments);
			Mock.VerifyAdd(this, expression, times(), failMessage);
		}

		/// <summary>
		///   Verifies that an event was removed from the mock.
		/// </summary>
		/// <param name="removeExpression">Expression to verify.</param>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		/// <example group="verification">
		///   This example assumes that the mock has been used, and later we want to verify
		///   that a given event handler was removed from an event:
		///   <code>
		///     var mock = new Mock&lt;IWarehouse&gt;();
		///
		///     ... // exercise mock
		///
		///     // Will throw if the test code didn't unsubscribe from the OnClosed event.
		///     mock.VerifyRemove(warehouse => warehouse.OnClose -= It.IsAny&lt;EventHandler&gt;());
		///   </code>
		/// </example>
		public void VerifyRemove(Action<T> removeExpression)
		{
			Guard.NotNull(removeExpression, nameof(removeExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(removeExpression, this.ConstructorArguments);
			Mock.VerifyRemove(this, expression, Times.AtLeastOnce(), null);
		}

		/// <summary>
		///   Verifies that an event was removed from the mock.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="removeExpression">Expression to verify.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyRemove(Action<T> removeExpression, Times times)
		{
			Guard.NotNull(removeExpression, nameof(removeExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(removeExpression, this.ConstructorArguments);
			Mock.VerifyRemove(this, expression, times, null);
		}

		/// <summary>
		///   Verifies that an event was removed from the mock.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="removeExpression">Expression to verify.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyRemove(Action<T> removeExpression, Func<Times> times)
		{
			Guard.NotNull(removeExpression, nameof(removeExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(removeExpression, this.ConstructorArguments);
			Mock.VerifyRemove(this, expression, times(), null);
		}

		/// <summary>
		///   Verifies that an event was removed from the mock, specifying a failure message.
		/// </summary>
		/// <param name="removeExpression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">The invocation was not performed on the mock.</exception>
		public void VerifyRemove(Action<T> removeExpression, string failMessage)
		{
			Guard.NotNull(removeExpression, nameof(removeExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(removeExpression, this.ConstructorArguments);
			Mock.VerifyRemove(this, expression, Times.AtLeastOnce(), failMessage);
		}

		/// <summary>
		///   Verifies that an event was removed from the mock, specifying a failure message.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="removeExpression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyRemove(Action<T> removeExpression, Times times, string failMessage)
		{
			Guard.NotNull(removeExpression, nameof(removeExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(removeExpression, this.ConstructorArguments);
			Mock.VerifyRemove(this, expression, times, failMessage);
		}

		/// <summary>
		///   Verifies that an event was removed from the mock, specifying a failure message.
		/// </summary>
		/// <param name="times">The number of times a method is expected to be called.</param>
		/// <param name="removeExpression">Expression to verify.</param>
		/// <param name="failMessage">Message to show if verification fails.</param>
		/// <exception cref="MockException">
		///   The invocation was not called the number of times specified by <paramref name="times"/>.
		/// </exception>
		public void VerifyRemove(Action<T> removeExpression, Func<Times> times, string failMessage)
		{
			Guard.NotNull(removeExpression, nameof(removeExpression));

			var expression = ExpressionReconstructor.Instance.ReconstructExpression(removeExpression, this.ConstructorArguments);
			Mock.VerifyRemove(this, expression, times(), failMessage);
		}

		/// <summary>
		/// Verifies that there were no calls other than those already verified.
		/// </summary>
		/// <exception cref="MockException">There was at least one invocation not previously verified.</exception>
		public void VerifyNoOtherCalls()
		{
			Mock.VerifyNoOtherCalls(this);
		}

#endregion

#region Raise

		/// <summary>
		///   Raises the event referenced in <paramref name="eventExpression"/> using the given <paramref name="args"/> argument.
		/// </summary>
		/// <exception cref="ArgumentException">
		///   The <paramref name="args"/> argument is invalid for the target event invocation,
		///   or the <paramref name="eventExpression"/> is not an event attach or detach expression.
		/// </exception>
		/// <example>
		///   The following example shows how to raise a
		///   <see cref="System.ComponentModel.INotifyPropertyChanged.PropertyChanged"/> event:
		///   <code>
		///     var mock = new Mock&lt;IViewModel&gt;();
		///     mock.Raise(x => x.PropertyChanged -= null, new PropertyChangedEventArgs("Name"));
		///   </code>
		/// </example>
		/// <example>
		///   This example shows how to invoke an event with a custom event arguments class
		///   in a view that will cause its corresponding presenter to react by changing its state:
		///   <code>
		///     var mockView = new Mock&lt;IOrdersView&gt;();
		///     var presenter = new OrdersPresenter(mockView.Object);
		///
		///     // Check that the presenter has no selection by default
		///     Assert.Null(presenter.SelectedOrder);
		///
		///     // Raise the event with a specific arguments data
		///     mockView.Raise(v => v.SelectionChanged += null, new OrderEventArgs { Order = new Order("moq", 500) });
		///
		///     // Now the presenter reacted to the event, and we have a selected order
		///     Assert.NotNull(presenter.SelectedOrder);
		///     Assert.Equal("moq", presenter.SelectedOrder.ProductName);
		///   </code>
		/// </example>
		public void Raise(Action<T> eventExpression, EventArgs args)
		{
			Mock.RaiseEvent(this, eventExpression, new object[] { this.Object, args });
		}

		/// <summary>
		///   Raises the event referenced in <paramref name="eventExpression"/> using the given <paramref name="args"/> argument for a non-<see cref="EventHandler"/>-typed event.
		/// </summary>
		/// <exception cref="ArgumentException">
		///   The <paramref name="args"/> arguments are invalid for the target event invocation,
		///   or the <paramref name="eventExpression"/> is not an event attach or detach expression.
		/// </exception>
		/// <example>
		///   The following example shows how to raise a custom event that does not adhere
		///   to the standard <c>EventHandler</c>:
		///   <code>
		///     var mock = new Mock&lt;IViewModel&gt;();
		///     mock.Raise(x => x.MyEvent -= null, "Name", bool, 25);
		///   </code>
		/// </example>
		public void Raise(Action<T> eventExpression, params object[] args)
		{
			Mock.RaiseEvent(this, eventExpression, args);
		}

#endregion
	}
}
