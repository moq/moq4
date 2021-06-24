// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD, and Contributors.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using System;
using System.Globalization;
using System.Linq.Expressions;
using Moq.Properties;
using Moq.Protected;
using Xunit;

namespace Moq.Tests
{
	public class StubExtensionsFixture
	{
		[Fact]
		public void ShouldStubIndexers()
		{
			var mock = new Mock<IFoo>();

			mock.SetupIndexer(f => f[1], "One");
			Assert.Equal("One", mock.Object[1]);
			mock.Object[2] = "Two";
			Assert.Equal("Two", mock.Object[2]);
			mock.Object[2] = "New";
			Assert.Equal("New", mock.Object[2]);
			Assert.Null(mock.Object[3]);
			Assert.Null(mock.Object[1, "2"]);
			mock.SetupIndexer(f => f[123, "X"], "123");
			Assert.Equal("123", mock.Object[123, "X"]);

			var foo1 = new Mock<IFoo>().Object;
			var foo2 = new Mock<IFoo>().Object;

			mock.SetupIndexer(f => f[foo1], "Foo1");
			Assert.Null(mock.Object[foo2]);
			Assert.Equal("Foo1", mock.Object[foo1]);

			var exception = Assert.Throws<ArgumentException>(() => mock.SetupIndexer(m => m.NotAnIndexer(1)));
			Expression<Func<IFoo, string>> badExpression = m => m.NotAnIndexer(1);
			var expectedMessage = string.Format(
					CultureInfo.CurrentCulture,
					Resources.SetupNotIndexerGetter,
					badExpression.ToStringFixed()
			);
			Assert.Contains(expectedMessage, exception.Message);
			Assert.Equal("expression", exception.ParamName);

			var protectedMock = new Mock<Protected>();
			var protectedLike = protectedMock.Protected().As<ProtectedLike>();
			protectedLike.SetupIndexer(m => m[1], "One");
			Assert.Equal("One", protectedMock.Object.GetIndex(1));
			protectedMock.Object.SetIndex(1, "New");
			Assert.Equal("New", protectedMock.Object.GetIndex(1));
			protectedMock.Object.SetIndex(2, "Two");
			Assert.Equal("Two", protectedMock.Object.GetIndex(2));
			Assert.Equal("New", protectedMock.Object.GetIndex(1));
		}

		[Fact]
		public void ShouldStubPropertyWithoutInitialValue()
		{
			var mock = new Mock<IFoo>();

			mock.SetupProperty(f => f.ValueProperty);

			Assert.Equal(0, mock.Object.ValueProperty);

			mock.Object.ValueProperty = 5;

			Assert.Equal(5, mock.Object.ValueProperty);
		}

		[Fact]
		public void ShouldStubPropertyWithInitialValue()
		{
			var mock = new Mock<IFoo>();

			mock.SetupProperty(f => f.ValueProperty, 5);

			Assert.Equal(5, mock.Object.ValueProperty);

			mock.Object.ValueProperty = 15;

			Assert.Equal(15, mock.Object.ValueProperty);
		}

		[Fact]
		public void StubsAllProperties()
		{
			var mock = new Mock<IFoo>();

			mock.SetupAllProperties();

			// Verify defaults
			Assert.Equal(default(int), mock.Object.ValueProperty);
			Assert.Null(mock.Object.Object);
			Assert.Null(mock.Object.Bar);
			Assert.Null(mock.Object.GetOnly);

			mock.Object.ValueProperty = 5;
			Assert.Equal(5, mock.Object.ValueProperty);

			var obj = new object();
			mock.Object.Object = obj;
			Assert.Same(obj, mock.Object.Object);

			var bar = new Mock<IBar>();
			mock.Object.Bar = bar.Object;
			Assert.Same(bar.Object, mock.Object.Bar);
		}

		[Fact]
		public void StubsAllCyrcularDependency()
		{
			var mock = new Mock<IHierarchy>();

			mock.SetupAllProperties();

			Assert.Null(mock.Object.Hierarchy);
		}

		[Fact]
		public void StubsAllHierarchy()
		{
			var mock = new Mock<IFoo>() { DefaultValue = DefaultValue.Mock };

			mock.SetupAllProperties();

			mock.Object.Bar.Value = 5;
			Assert.Equal(5, mock.Object.Bar.Value);
		}

		[Fact]
		public void StubsInheritedInterfaceProperties()
		{
			var mock = new Mock<IBaz>();

			mock.SetupAllProperties();

			mock.Object.Value = 5;
			Assert.Equal(5, mock.Object.Value);

			mock.Object.Name = "foo";
			Assert.Equal("foo", mock.Object.Name);
		}

		[Fact]
		public void StubsInheritedClassProperties()
		{
			var mock = new Mock<Base>();

			mock.SetupAllProperties();

			mock.Object.BaseValue = 5;
			Assert.Equal(5, mock.Object.BaseValue);

			mock.Object.Value = 10;
			Assert.Equal(10, mock.Object.Value);
		}

		[Fact]
		public void Property_stubbed_by_SetupAllProperties_during_DefaultValue_Mock_has_initial_value_included_in_verification()
		{
			var mock = new Mock<IFoo> { DefaultValue = DefaultValue.Mock };
			mock.SetupAllProperties();

			var inner = Mock.Get(mock.Object.Bar);
			inner.SetupGet(m => m.Value).Verifiable();

			Assert.Throws<MockException>(() => mock.Verify());
		}

		[Fact]
		public void Property_stubbed_by_SetupAllProperties_during_DefaultValue_Mock_can_retain_new_values()
		{
			var mock = new Mock<IFoo> { DefaultValue = DefaultValue.Mock };
			mock.SetupAllProperties();

			mock.Object.Bar = new Bar { Value = 1 };
			Assert.Equal(1, mock.Object.Bar.Value);

			mock.Object.Bar = new Bar { Value = 2 };
			Assert.Equal(2, mock.Object.Bar.Value);
		}

		[Fact]
		public void Property_stubbed_by_SetupAllProperties_during_DefaultValue_Mock_can_retain_new_values_after_initial_value_queried()
		{
			var mock = new Mock<IFoo> { DefaultValue = DefaultValue.Mock };
			mock.SetupAllProperties();

			_ = mock.Object.Bar;  // this is the only difference between this test and the previous one

			mock.Object.Bar = new Bar { Value = 1 };
			Assert.Equal(1, mock.Object.Bar.Value);

			mock.Object.Bar = new Bar { Value = 2 };
			Assert.Equal(2, mock.Object.Bar.Value);
		}
		
		[Fact]
		public void Property_stubbed_by_SetupAllProperties_should_capture_DefaultValue_behaviour()
		{
			var mock = new Mock<IFoo>() { DefaultValue = DefaultValue.Mock };
			mock.SetupAllProperties();
			mock.DefaultValue = DefaultValue.Empty;

			mock.Object.Bar.Value = 5;
			Assert.Equal(5, mock.Object.Bar.Value);
		}
		
		[Fact]
		public void Property_stubbed_by_SetupAllProperties_should_capture_DefaultValue_behaviour_for_inner_mocks()
		{
			var mock = new Mock<IHierarchy>() { DefaultValue = DefaultValue.Mock };
			mock.SetupAllProperties();
			mock.DefaultValue = DefaultValue.Empty;

			Assert.NotNull(mock.Object.Hierarchy.Hierarchy);
		}
		
		[Fact]
		public void Property_stubbed_by_SetupAllProperties_should_use_parent_DefaultValue_behaviour_for_inner_mocks()
		{
			var mock = new Mock<IHierarchy>() { DefaultValue = DefaultValue.Mock };
			mock.SetupAllProperties();
			Mock.Get(mock.Object.Hierarchy).DefaultValue = DefaultValue.Empty;

			Assert.NotNull(mock.Object.Hierarchy.Hierarchy);
		}

		public abstract class WriteOnlyProperty
		{
			public abstract string Test { set; }
		}

		[Theory]
		[InlineData(MockBehavior.Strict)]
		[InlineData(MockBehavior.Loose)]
		public void SetupAllProperties_should_setup_write_only_properties(MockBehavior mockBehavior)
		{
			var mock = new Mock<WriteOnlyProperty>(mockBehavior);
			mock.SetupAllProperties();
			
			mock.Object.Test = "test";
		}

		public interface IWithReadOnlyProperty
		{
			string WriteAccessInDerived { get; }
		}

		public abstract class AddWriteAccessToInterface : IWithReadOnlyProperty
		{
			public abstract string WriteAccessInDerived { get; set; }
		}

		[Fact]
		public void SetupAllProperties_should_setup_properties_from_interface_with_write_access_added_in_derived()
		{
			var mock = new Mock<AddWriteAccessToInterface>();
			mock.SetupAllProperties();
			IWithReadOnlyProperty asInterface = mock.Object;

			mock.Object.WriteAccessInDerived = "test";
			
			Assert.Equal("test", mock.Object.WriteAccessInDerived);
			Assert.Equal("test", asInterface.WriteAccessInDerived);
		}
		
		[Fact]
		public void SetupAllProperties_should_setup_properties_from_interface_with_write_access_added_in_derived_if_interface_is_reimplemented()
		{
			var mock = new Mock<AddWriteAccessToInterface>();
			mock.SetupAllProperties();
			IWithReadOnlyProperty asReimplementedInterface = mock.As<IWithReadOnlyProperty>().Object;

			mock.Object.WriteAccessInDerived = "test";
			
			Assert.Equal("test", mock.Object.WriteAccessInDerived);
			Assert.Equal("test", asReimplementedInterface.WriteAccessInDerived);
		}

		[Fact]
		public void SetupAllProperties_should_override_previous_SetupAllProperties()
		{
			var mock = new Mock<IBar>();

			mock.SetReturnsDefault(1);
			mock.SetupAllProperties();
			Assert.Equal(1, mock.Object.Value);

			mock.Object.Value = 2;

			mock.SetupAllProperties();
			Assert.Equal(1, mock.Object.Value);
		}
		
		[Fact]
		public void SetupAllProperties_should_override_regular_setups()
		{
			var mock = new Mock<IBar>();
			mock.Setup(x => x.Value).Returns(1);

			mock.SetupAllProperties();
			
			Assert.Equal(0, mock.Object.Value);
		}

		[Fact]
		public void SetupAllProperties_retains_value_of_derived_read_write_property_that_overrides_only_setter()
		{
			var mock = new Mock<OverridesOnlySetter>();
			mock.SetupAllProperties();
			mock.Object.Property = "value";
			Assert.Equal("value", mock.Object.Property);
		}

		[Fact]
		public void SetupProperty_retains_value_of_derived_read_write_property_that_overrides_only_setter()
		{
			var mock = new Mock<OverridesOnlySetter>();
			mock.SetupProperty(m => m.Property);
			mock.Object.Property = "value";
			Assert.Equal("value", mock.Object.Property);
		}

		[Fact]
		public void SetupProperty_retains_value_of_derived_read_write_property_that_overrides_only_getter()
		{
			var mock = new Mock<OverridesOnlyGetter>();
			mock.SetupProperty(m => m.Property);
			mock.Object.Property = "value";
			Assert.Equal("value", mock.Object.Property);
		}

		private object GetValue() { return new object(); }

		public interface IFoo
		{
			int ValueProperty { get; set; }
			object Object { get; set; }
			IBar Bar { get; set; }
			object GetOnly { get; }
			string this[int key] { get;set; }
			string this[int key,string key2] { get; set; }
			string this[IFoo key] { get; set; }
			string NotAnIndexer(int notAKey);
		}

		public abstract class Protected
		{
			protected abstract string this[int key] { get;set; }
			public string GetIndex(int key)
			{
				return this[key];
			}
			public void SetIndex(int key, string value)
			{
				this[key] = value;
			}
		}

		public interface ProtectedLike {
			string this[int key] { get; set; }
		}

		public class Derived : Base
		{
			public string Name { get; set; }
		}

		public abstract class Base : IBar
		{
			public int BaseValue { get; set; }
			public int Value { get; set; }
		}

		public interface IBar
		{
			int Value { get; set; }
		}

		class Bar : IBar
		{
			public int Value { get; set; }
		}

		public interface IBaz : IBar
		{
			string Name { get; set; }
		}

		public interface IHierarchy
		{
			IHierarchy Hierarchy { get; set; }
		}

		public class WithAutoProperty
		{
			public virtual object Property { get; set; }
		}

		public class OverridesOnlySetter : WithAutoProperty
		{
			public override object Property { set => base.Property = value; }
		}

		public class OverridesOnlyGetter : WithAutoProperty
		{
			public override object Property { get => base.Property; }
		}
	}
}
